// Bazarish project (c) 2026
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace bazarish {

// RFC 3986: everything but the unreserved characters becomes %XX.
std::string percentEncode(const std::string& value);
// A malformed escape is kept as it stands.
std::string percentDecode(const std::string& value);
// A form field: '+' is a space, then escapes as above.
std::string formDecode(const std::string& value);

struct QueryField {
    std::string key;
    std::string value;
};
// The fields of a query in order, values as written; nothing when one of them has no '='.
std::optional<std::vector<QueryField>> queryFields(const std::string& query);

}  // namespace bazarish
