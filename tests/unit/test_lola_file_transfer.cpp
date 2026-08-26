#include <gtest/gtest.h>
#include <string>

namespace nvhttp {
  std::string lola_sha256(std::string_view content);
  bool lola_safe_id(const std::string &value);
  bool lola_safe_name(const std::string &value);
}

TEST(LoLaFileTransfer, AcceptsSafeOpaqueIdentifiers) {
  EXPECT_TRUE(nvhttp::lola_safe_id("transfer_2026-08-26_A"));
  EXPECT_TRUE(nvhttp::lola_safe_id("a"));
}

TEST(LoLaFileTransfer, RejectsUnsafeOpaqueIdentifiers) {
  EXPECT_FALSE(nvhttp::lola_safe_id(""));
  EXPECT_FALSE(nvhttp::lola_safe_id("../escape"));
  EXPECT_FALSE(nvhttp::lola_safe_id("contains space"));
  EXPECT_FALSE(nvhttp::lola_safe_id(std::string(129, 'a')));
}

TEST(LoLaFileTransfer, AcceptsBaseFileNames) {
  EXPECT_TRUE(nvhttp::lola_safe_name("report.pdf"));
  EXPECT_TRUE(nvhttp::lola_safe_name("model-v2_01.step"));
}

TEST(LoLaFileTransfer, RejectsPathsAndInvalidNames) {
  EXPECT_FALSE(nvhttp::lola_safe_name(""));
  EXPECT_FALSE(nvhttp::lola_safe_name("."));
  EXPECT_FALSE(nvhttp::lola_safe_name(".."));
  EXPECT_FALSE(nvhttp::lola_safe_name("../secret.txt"));
  EXPECT_FALSE(nvhttp::lola_safe_name("folder/file.txt"));
  EXPECT_FALSE(nvhttp::lola_safe_name("folder\\file.txt"));
  EXPECT_FALSE(nvhttp::lola_safe_name("bad:name.txt"));
  EXPECT_FALSE(nvhttp::lola_safe_name(std::string("bad\x01name.txt", 12)));
  EXPECT_FALSE(nvhttp::lola_safe_name(std::string(256, 'a')));
}

TEST(LoLaFileTransfer, UsesStandardLowercaseSha256) {
  EXPECT_EQ(
    nvhttp::lola_sha256("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
}
