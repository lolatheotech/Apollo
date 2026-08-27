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
        if (cursor == LoadCursorA(nullptr, id)) {
          return name;
        }
      }
      return "unsupported";
    }

    bool parse_u32(const char *text, DWORD &value) {
      if (!text || !*text) {
        return false;
      }
      const auto end = text + std::strlen(text);
      const auto result = std::from_chars(text, end, value);
      return result.ec == std::errc {} && result.ptr == end;
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
        if (!state_ || active_session == 0xFFFFFFFF || active_session != session_id_ ||
            !child_ || WaitForSingleObject(child_, 0) == WAIT_OBJECT_0) {
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
        if (child_) {
          if (WaitForSingleObject(child_, 0) == WAIT_TIMEOUT) {
            TerminateProcess(child_, 0);
            WaitForSingleObject(child_, 1000);
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
        SECURITY_ATTRIBUTES security {sizeof(security), descriptor, FALSE};
        mapping_ = CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0,
                                      sizeof(shared_state_t), mapping_name_.c_str());
        LocalFree(descriptor);
        if (!mapping_) {
          BOOST_LOG(error) << "Cursor broker mapping creation failed: " << GetLastError();
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
                               mapping_name_ + L"\" " + std::to_wstring(GetCurrentProcessId());
        STARTUPINFOW startup {};
        startup.cb = sizeof(startup);
        wchar_t desktop[] = L"winsta0\\default";
        startup.lpDesktop = desktop;
        PROCESS_INFORMATION process {};
        void *environment = nullptr;
        CreateEnvironmentBlock(&environment, user_token, FALSE);
        const BOOL created = CreateProcessAsUserW(
          user_token, executable, command.data(), nullptr, nullptr, FALSE,
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
    DWORD parent_pid = 0;
    if (mapping_name.rfind(L"Global\\LoLaCursorBroker-{", 0) != 0 ||
        mapping_name.size() > 80 || !parse_u32(argv[1], parent_pid)) {
      return 2;
    }

    HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, parent_pid);
    HANDLE mapping = OpenFileMappingW(FILE_MAP_WRITE, FALSE, mapping_name.c_str());
    if (!parent || !mapping) {
      if (parent) CloseHandle(parent);
      if (mapping) CloseHandle(mapping);
      return 3;
    }
    auto *state = static_cast<shared_state_t *>(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(shared_state_t)));
    if (!state) {
      CloseHandle(mapping);
      CloseHandle(parent);
      return 3;
    }

    const DWORD session_id = WTSGetActiveConsoleSessionId();
    while (WaitForSingleObject(parent, sample_period_ms) == WAIT_TIMEOUT) {
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
    CloseHandle(parent);
    return 0;
  }

  snapshot_t snapshot() {
    return manager().read();
  }
}
