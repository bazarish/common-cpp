// Bazarish project (c) 2026
#pragma once

#include "bazarish/Errors.hpp"
#include "bazarish/HttpServer.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace bazarish::http {

inline constexpr int kStatusOk = 200;

Response jsonResponse(const nlohmann::json& body, int status = kStatusOk);
Response errorResponse(int status, ErrorCode code, const std::string& message);

}  // namespace bazarish::http
