// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <string>

typedef struct ssl_st SSL;

namespace bazarish::tls {

struct Credential {
    std::filesystem::path certificate;
    std::filesystem::path key;
    std::string pin;
};

Credential selfSigned(const std::filesystem::path& stateDir);

std::string pinOf(SSL* connection);
std::string pinOfCertificate(const std::filesystem::path& certificate);

}  // namespace bazarish::tls
