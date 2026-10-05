// Bazarish project (c) 2026
#pragma once

#include <nlohmann/json.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace bazarish {

inline constexpr int kMinPort = 1;
inline constexpr int kMaxPort = 65535;

nlohmann::json readJsonFile(const std::filesystem::path& path);

class ConfigFile {
public:
    explicit ConfigFile(std::filesystem::path path);

    const std::filesystem::path& path() const { return path_; }

    nlohmann::json read() const;

    void set(const std::vector<std::string>& keys, const nlohmann::json& value);

private:
    std::filesystem::path path_;
};

class ConfigView {
public:
    explicit ConfigView(nlohmann::json document);

    std::string text(const std::string& path, const std::string& fallback = {}) const;
    std::int64_t number(const std::string& path, std::int64_t fallback) const;
    bool flag(const std::string& path, bool fallback) const;
    std::vector<std::string> list(const std::string& path) const;

    bool has(const std::string& path) const;

    struct Endpoint {
        std::string host;
        int port = 0;
    };
    std::optional<Endpoint> endpoint(const std::string& path) const;

    const nlohmann::json& document() const { return document_; }

private:
    const nlohmann::json* find(const std::string& path) const;

    nlohmann::json document_;
};

template <class T>
void setIfChanged(ConfigFile& file, std::vector<std::string> keys, const T& wanted,
    const T& current)
{
    if (!(wanted == current)) {
        file.set(std::move(keys), wanted);
    }
}

void readEndpointInto(
    const nlohmann::json& body, const std::string& key, std::string& host, int& port);

std::string configWithValue(
    const std::string& text, const std::vector<std::string>& keys, const nlohmann::json& value);

}  // namespace bazarish
