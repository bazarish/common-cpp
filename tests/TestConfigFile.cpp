// Bazarish project (c) 2026
#include <bazarish/ConfigFile.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;

namespace {

// The file an operator wrote: their order, their spacing, their notes.
const char* const kConfig = R"({
  // how much every account gets
  "freeStorageBytes": 52428800,
  "portal": {
    "message": "Bazarish test stand.",   /* shown by the client */
    "facades": ["http://one.example", "http://two.example"]
  },
  "registration": {
    "requireApproval": false,
    "ttlDays": 7
  }
}
)";

void testPatchKeepsEverythingElse()
{
    const std::string patched
        = configWithValue(kConfig, {"registration", "requireApproval"}, true);
    CHECK(patched.find("\"requireApproval\": true") != std::string::npos);
    // The operator's notes, order and spacing are untouched.
    CHECK(patched.find("// how much every account gets") != std::string::npos);
    CHECK(patched.find("/* shown by the client */") != std::string::npos);
    CHECK(patched.find("\"ttlDays\": 7") != std::string::npos);
    CHECK(patched.find("\"http://two.example\"") != std::string::npos);
    CHECK(patched.find("\"freeStorageBytes\": 52428800") != std::string::npos);
    // Only the one value moved: everything before the change is byte for byte.
    const std::size_t at = kConfig ? std::string(kConfig).find("\"requireApproval\"") : 0;
    CHECK(patched.compare(0, at, kConfig, at) == 0);
}

void testPatchesAtTheTopLevel()
{
    const std::string patched = configWithValue(kConfig, {"freeStorageBytes"}, 20971520);
    CHECK(patched.find("\"freeStorageBytes\": 20971520") != std::string::npos);
    CHECK(patched.find("\"requireApproval\": false") != std::string::npos);
}

void testStringsAreEscaped()
{
    const std::string patched = configWithValue(
        kConfig, {"registration", "message"}, "He said \"no\", then left\n");
    CHECK(patched.find("\"message\": \"He said \\\"no\\\", then left\\n\"") != std::string::npos);
    // The portal's own message, which shares the key name, is not the one changed.
    CHECK(patched.find("\"message\": \"Bazarish test stand.\"") != std::string::npos);
}

void testWritesKeysTheFileDoesNotHave()
{
    const std::string added = configWithValue(kConfig, {"registration", "message"}, "Ping me");
    CHECK(added.find("\"message\": \"Ping me\"") != std::string::npos);
    CHECK(added.find("\"requireApproval\": false") != std::string::npos);
    CHECK(nlohmann::json::parse(added, nullptr, true, true)
              .at("registration")
              .at("message")
              .get<std::string>()
        == "Ping me");

    // A whole branch the file never had.
    const std::string branch = configWithValue(kConfig, {"limits", "maxDevices"}, 4);
    const nlohmann::json parsed = nlohmann::json::parse(branch, nullptr, true, true);
    CHECK(parsed.at("limits").at("maxDevices").get<int>() == 4);
    CHECK(parsed.at("freeStorageBytes").get<std::uint64_t>() == 52428800);

    // An empty object takes its first key.
    const std::string empty = configWithValue("{\n  \"registration\": {}\n}\n",
        {"registration", "ttlDays"}, 3);
    CHECK(nlohmann::json::parse(empty).at("registration").at("ttlDays").get<int>() == 3);
}

void testRefusesWhatItCannotPatch()
{
    bool threw = false;
    try {
        // freeStorageBytes is a number, so it holds no keys.
        (void)configWithValue(kConfig, {"freeStorageBytes", "inner"}, 1);
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);

    bool notAnObject = false;
    try {
        (void)configWithValue("[1, 2]", {"a"}, 1);
    } catch (const std::exception&) {
        notAnObject = true;
    }
    CHECK(notAnObject);
}

}  // namespace

int main()
{
    testPatchKeepsEverythingElse();
    testPatchesAtTheTopLevel();
    testStringsAreEscaped();
    testWritesKeysTheFileDoesNotHave();
    testRefusesWhatItCannotPatch();
    std::printf("TestConfigFile: all checks passed\n");
    return 0;
}
