// Bazarish project (c) 2026
#include "bazarish/PlainText.hpp"

#include "TestUtil.hpp"

#include <string>

using bazarish::kMaxFileNameBytes;
using bazarish::safeFileName;

namespace {

constexpr std::size_t kOverlongStem = 400;
constexpr int kWideLetters = 200;
constexpr std::size_t kWideLetterBytes = 2;

}  // namespace

int main()
{
    CHECK(safeFileName("../x") == "x");
    CHECK(safeFileName("/etc/x") == "x");
    CHECK(safeFileName("C:\\x") == "x");
    CHECK(safeFileName("a\\..\\..\\x.bat") == "x.bat");
    CHECK(safeFileName("../.config/autostart/x.desktop") == "x.desktop");
    CHECK(safeFileName("x\u202Egnp.exe") == "xgnp.exe");
    CHECK(safeFileName("a\u2066b\u200Fc\x01" "d") == "abcd");
    CHECK(safeFileName("CON") == "_CON");
    CHECK(safeFileName("nul.txt") == "_nul.txt");
    CHECK(safeFileName("COM7") == "_COM7");
    CHECK(safeFileName("COM0") == "COM0");
    CHECK(safeFileName("CONSOLE") == "CONSOLE");
    CHECK(safeFileName("a. ") == "a");
    CHECK(safeFileName("..") == "file");
    CHECK(safeFileName("") == "file");
    CHECK(safeFileName("dir/") == "file");
    CHECK(safeFileName("a:b?.txt") == "a_b_.txt");
    CHECK(safeFileName("\xff\xfeok") == "ok");
    CHECK(safeFileName("счёт.pdf") == "счёт.pdf");

    const std::string longName = std::string(kOverlongStem, 'y') + ".tar.gz";
    const std::string cut = safeFileName(longName);
    CHECK(cut.size() == kMaxFileNameBytes);
    CHECK(cut.substr(cut.size() - 3) == ".gz");

    std::string wide;
    for (int i = 0; i < kWideLetters; ++i) {
        wide += "ж";
    }
    const std::string cutWide = safeFileName(wide);
    CHECK(cutWide.size() <= kMaxFileNameBytes);
    CHECK(cutWide.size() % kWideLetterBytes == 0);
    return 0;
}
