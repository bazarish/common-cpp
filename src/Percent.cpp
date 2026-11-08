// Bazarish project (c) 2026
#include "bazarish/Percent.hpp"

#include "bazarish/Bytes.hpp"

#include <algorithm>
#include <cstddef>

namespace bazarish {

namespace {

constexpr const char* kHexDigits = "0123456789ABCDEF";
constexpr unsigned kNibbleBits = 4;
constexpr unsigned kLowNibble = 0x0F;
constexpr std::size_t kEscapeDigits = 2;

bool unreserved(const unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
        || c == '-' || c == '_' || c == '.' || c == '~';
}

}  // namespace

std::string percentEncode(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
        if (unreserved(c)) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHexDigits[c >> kNibbleBits]);
            out.push_back(kHexDigits[c & kLowNibble]);
        }
    }
    return out;
}

std::string percentDecode(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + kEscapeDigits < value.size()) {
            const int high = hexDigitValue(value[i + 1]);
            const int low = hexDigitValue(value[i + 2]);
            if (high >= 0 && low >= 0) {
                out.push_back(static_cast<char>((high << kNibbleBits) | low));
                i += kEscapeDigits;
                continue;
            }
        }
        out.push_back(value[i]);
    }
    return out;
}

std::optional<std::vector<QueryField>> queryFields(const std::string& query)
{
    std::vector<QueryField> fields;
    if (query.empty()) {
        return fields;
    }
    std::size_t pos = 0;
    while (true) {
        const std::size_t amp = query.find('&', pos);
        const std::string pair = query.substr(pos, amp == std::string::npos ? amp : amp - pos);
        const std::size_t eq = pair.find('=');
        if (eq == std::string::npos) {
            return std::nullopt;
        }
        fields.push_back({pair.substr(0, eq), pair.substr(eq + 1)});
        if (amp == std::string::npos) {
            return fields;
        }
        pos = amp + 1;
    }
}

std::string formDecode(const std::string& value)
{
    std::string spaced = value;
    std::replace(spaced.begin(), spaced.end(), '+', ' ');
    return percentDecode(spaced);
}

}  // namespace bazarish
