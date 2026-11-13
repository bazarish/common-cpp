// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Devices.hpp>

#include <nlohmann/json.hpp>

#include <string>

namespace bazarish::client {

inline constexpr const char* kAuthorshipField = "auth";

// Names the signing device; a first letter to an account also carries the device's certificate.
void signAuthorship(nlohmann::json& content, const DeviceCredential& device, bool withCert);

struct Author {
    std::string account;
    std::string device;
};

std::string authorDevice(const nlohmann::json& content);
// Empty when the letter does not carry one.
Bytes carriedCert(const nlohmann::json& content);

// Checked against the certificate carried, else against the account's device in `known`.
Author authorOf(const nlohmann::json& content, const DeviceBook& known);

}  // namespace bazarish::client
