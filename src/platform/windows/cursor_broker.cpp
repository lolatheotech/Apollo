/**
 * @file src/platform/windows/cursor_broker.cpp
 * @brief Supplies interactive-user cursor state to the Apollo service.
 */

#include "cursor_broker.h"

#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "../../logging.h"

namespace platf::cursor_broker {
  namespace {
    constexpr DWORD sample_period_ms = 25;
    constexpr ULONGLONG stale_after_ms = 1000;
    constexpr std::size_t shape_capacity = 24;

    struct shared_state_t {
      volatile LONG sequence_lock;
      DWORD session_id;
      DWORD visible;
      std::uint64_t cursor_sequence;
      ULONGLONG sample_tick;
      char shape[shape_capacity];
    };

    struct cursor_fingerprint_t {
      DWORD hotspot_x {};
      DWORD hotspot_y {};
      LONG width {};
      LONG height {};
      std::vector<std::uint8_t> mask;
      std::vector<std::uint8_t> color;
    };

    bool bitmap_bytes(HBITMAP bitmap, LONG &width, LONG &height, std::vector<std::uint8_t> &bytes) {
      if (!bitmap) return true;
      BITMAP description {};
      if (!GetObjectW(bitmap, sizeof(description), &description) || description.bmWidth <= 0 || description.bmHeight <= 0) {
        return false;
      }
      width = description.bmWidth;
      height = description.bmHeight;
      const auto size = static_cast<std::size_t>(description.bmWidthBytes) * description.bmHeight;
      bytes.resize(size);
      return size == 0 || GetBitmapBits(bitmap, static_cast<LONG>(size), bytes.data()) == static_cast<LONG>(size);
    }

    bool fingerprint(HCURSOR cursor, cursor_fingerprint_t &result) {
      ICONINFO info {};
      if (!cursor || !GetIconInfo(cursor, &info)) return false;
      result.hotspot_x = info.xHotspot;
      result.hotspot_y = info.yHotspot;
      LONG mask_width = 0, mask_height = 0, color_width = 0, color_height = 0;
      const bool ok = bitmap_bytes(info.hbmMask, mask_width, mask_height, result.mask) &&
                      bitmap_bytes(info.hbmColor, color_width, color_height, result.color);
      if (info.hbmMask) DeleteObject(info.hbmMask);
      if (info.hbmColor) DeleteObject(info.hbmColor);
      result.width = color_width ? color_width : mask_width;
      result.height = color_height ? color_height : mask_height;
      return ok;
    }

    bool cursors_equivalent(HCURSOR left, HCURSOR right) {
      if (left == right) return true;
      cursor_fingerprint_t a, b;
      return fingerprint(left, a) && fingerprint(right, b) &&
             a.hotspot_x == b.hotspot_x && a.hotspot_y == b.hotspot_y &&
             a.width == b.width && a.height == b.height && a.mask == b.mask && a.color == b.color;
    }

    const char *shape_name(HCURSOR cursor) {
      const std::pair<LPCSTR, const char *> known[] = {
        {IDC_ARROW, "arrow"}, {IDC_IBEAM, "ibeam"}, {IDC_WAIT, "wait"},
        {IDC_CROSS, "crosshair"}, {IDC_UPARROW, "uparrow"},
        {IDC_SIZENWSE, "size_nwse"}, {IDC_SIZENESW, "size_nesw"},
        {IDC_SIZEWE, "size_we"}, {IDC_SIZENS, "size_ns"},
        {IDC_SIZEALL, "size_all"}, {IDC_NO, "forbidden"},
        {IDC_HAND, "hand"}, {IDC_APPSTARTING, "busy"}, {IDC_HELP, "help"}
      };
      for (const auto &[id, name] : known) {
        if (cursors_equivalent(cursor, LoadCursorA(nullptr, id))) return name;
      }
      return "unsupported";
    }

    std::wstring widen_ascii(const char *text) {
      std::wstring result;
      if (text) {
        while (*text) {
          const unsigned char c = static_cast<unsigned char>(*text++);
          if (c < 0x20 || c > 0x7e) {
            return {};
          }
          result.push_back(static_cast<wchar_t>(c));
        }
      }
      return result;
    }

    class manager_t {
    public:
      ~manager_t() {
        stop();
      }

      snapshot_t read() {
        std::lock_guard lock(mutex_);
        const DWORD active_session = WTSGetActiveConsoleSessionId();
        const bool child_exited = child_ && WaitForSingleObject(child_, 0) == WAIT_OBJECT_0;
        if (child_exited) {
          DWORD exit_code = 0;
          GetExitCodeProcess(child_, &exit_code);
          BOOST_LOG(warning) << "Cursor broker exited with code " << exit_code;
        }
        if (!state_ || active_session == 0xFFFFFFFF || active_session != session_id_ ||
            !child_ || child_exited) {
          start(active_session);
        }
        if (!state_) {
          return {};
        }

        shared_state_t copy {};
        for (int attempt = 0; attempt < 3; ++attempt) {
          const LONG before = InterlockedCompareExchange(&state_->sequence_lock, 0, 0);
          if (before & 1) {
            continue;
          }
          MemoryBarrier();
          std::memcpy(&copy, state_, sizeof(copy));
          MemoryBarrier();
          const LONG after = InterlockedCompareExchange(&state_->sequence_lock, 0, 0);
          if (before == after && !(after & 1)) {
            if (copy.session_id != session_id_ || !copy.sample_tick ||
                GetTickCount64() - copy.sample_tick > stale_after_ms) {
              return {};
            }
            copy.shape[shape_capacity - 1] = '\0';
            return {copy.visible != 0, copy.shape, copy.cursor_sequence};
          }
        }
        return {};
      }

    private:
      void stop() {
        if (lifetime_event_) {
          SetEvent(lifetime_event_);
        }
        if (child_) {
          if (WaitForSingleObject(child_, 0) == WAIT_TIMEOUT) {
            if (WaitForSingleObject(child_, 1000) == WAIT_TIMEOUT) {
              TerminateProcess(child_, 0);
              WaitForSingleObject(child_, 1000);
            }
          }
          CloseHandle(child_);
          child_ = nullptr;
        }
        if (state_) {
          UnmapViewOfFile(state_);
          state_ = nullptr;
        }
        if (mapping_) {
          CloseHandle(mapping_);
          mapping_ = nullptr;
        }
        if (lifetime_event_) {
          CloseHandle(lifetime_event_);
          lifetime_event_ = nullptr;
        }
        session_id_ = 0xFFFFFFFF;
      }

      void start(DWORD active_session) {
        stop();
        if (active_session == 0xFFFFFFFF) {
          return;
        }

        GUID guid {};
        wchar_t guid_text[40] {};
        if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(guid, guid_text, 40)) {
          BOOST_LOG(error) << "Cursor broker could not generate a private mapping name";
          return;
        }
        mapping_name_ = L"Global\\LoLaCursorBroker-" + std::wstring(guid_text);

        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
              L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)", SDDL_REVISION_1,
              &descriptor, nullptr)) {
          BOOST_LOG(error) << "Cursor broker security descriptor failed: " << GetLastError();
          return;
        }
        SECURITY_ATTRIBUTES security {sizeof(security), descriptor, TRUE};
        mapping_ = CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0,
                                      sizeof(shared_state_t), mapping_name_.c_str());
        lifetime_event_ = CreateEventW(&security, TRUE, FALSE, nullptr);
        LocalFree(descriptor);
        if (!mapping_ || !lifetime_event_) {
          BOOST_LOG(error) << "Cursor broker IPC creation failed: " << GetLastError();
          stop();
          return;
        }
        state_ = static_cast<shared_state_t *>(MapViewOfFile(mapping_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(shared_state_t)));
        if (!state_) {
          BOOST_LOG(error) << "Cursor broker mapping view failed: " << GetLastError();
          stop();
          return;
        }
        std::memset(state_, 0, sizeof(*state_));

        HANDLE user_token = nullptr;
        if (!WTSQueryUserToken(active_session, &user_token)) {
          BOOST_LOG(warning) << "Cursor broker cannot query active user token: " << GetLastError();
          stop();
          return;
        }

        wchar_t executable[MAX_PATH] {};
        const DWORD executable_length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
        if (!executable_length || executable_length == MAX_PATH) {
          CloseHandle(user_token);
          stop();
          return;
        }
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --cursor-broker \"" +
                               mapping_name_ + L"\" " +
                               std::to_wstring(reinterpret_cast<std::uintptr_t>(lifetime_event_));
        STARTUPINFOW startup {};
        startup.cb = sizeof(startup);
        wchar_t desktop[] = L"winsta0\\default";
        startup.lpDesktop = desktop;
        PROCESS_INFORMATION process {};
        void *environment = nullptr;
        CreateEnvironmentBlock(&environment, user_token, FALSE);
        const BOOL created = CreateProcessAsUserW(
          user_token, executable, command.data(), nullptr, nullptr, TRUE,
          CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, environment, nullptr, &startup, &process);
        if (environment) {
          DestroyEnvironmentBlock(environment);
        }
        CloseHandle(user_token);
        if (!created) {
          BOOST_LOG(error) << "Cursor broker launch failed: " << GetLastError();
          stop();
          return;
        }
        CloseHandle(process.hThread);
        child_ = process.hProcess;
        session_id_ = active_session;
        BOOST_LOG(info) << "Cursor broker launched in interactive session " << active_session;
      }

      std::mutex mutex_;
      HANDLE mapping_ {nullptr};
      HANDLE child_ {nullptr};
      HANDLE lifetime_event_ {nullptr};
      shared_state_t *state_ {nullptr};
      DWORD session_id_ {0xFFFFFFFF};
      std::wstring mapping_name_;
    };

    manager_t &manager() {
      static manager_t instance;
      return instance;
    }
  }

  int run(int argc, char **argv) {
    if (argc != 2) {
      return 2;
    }
    const auto mapping_name = widen_ascii(argv[0]);
    std::uintptr_t inherited_event_value = 0;
    const auto event_text = argv[1];
    const auto event_end = event_text + std::strlen(event_text);
    const auto parsed = std::from_chars(event_text, event_end, inherited_event_value);
    if (mapping_name.rfind(L"Global\\LoLaCursorBroker-{", 0) != 0 ||
        mapping_name.size() > 80 || parsed.ec != std::errc {} || parsed.ptr != event_end || !inherited_event_value) {
      return 2;
    }

    HANDLE lifetime_event = reinterpret_cast<HANDLE>(inherited_event_value);
    HANDLE mapping = OpenFileMappingW(FILE_MAP_WRITE, FALSE, mapping_name.c_str());
    if (!mapping) return 32;
    auto *state = static_cast<shared_state_t *>(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(shared_state_t)));
    if (!state) {
      CloseHandle(mapping);
      CloseHandle(lifetime_event);
      return 33;
    }

    const DWORD session_id = WTSGetActiveConsoleSessionId();
    while (WaitForSingleObject(lifetime_event, sample_period_ms) == WAIT_TIMEOUT) {
      CURSORINFO info {};
      info.cbSize = sizeof(info);
      const bool valid = GetCursorInfo(&info) != FALSE;
      const char *shape = valid ? shape_name(info.hCursor) : "unsupported";

      InterlockedIncrement(&state->sequence_lock);
      MemoryBarrier();
      state->session_id = session_id;
      state->visible = valid && (info.flags & CURSOR_SHOWING) ? 1 : 0;
      state->cursor_sequence = valid ? reinterpret_cast<std::uintptr_t>(info.hCursor) : 0;
      state->sample_tick = GetTickCount64();
      std::strncpy(state->shape, shape, shape_capacity - 1);
      state->shape[shape_capacity - 1] = '\0';
      MemoryBarrier();
      InterlockedIncrement(&state->sequence_lock);
    }

    UnmapViewOfFile(state);
    CloseHandle(mapping);
    CloseHandle(lifetime_event);
    return 0;
  }

  snapshot_t snapshot() {
    return manager().read();
  }
}
