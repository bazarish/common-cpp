// Bazarish project (c) 2026
#include "bazarish/Cms.hpp"

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include <memory>
#include <stdexcept>

namespace {

using bazarish::Bytes;

struct BioDeleter {
    void operator()(BIO* bio) const
    {
        BIO_free(bio);
    }
};
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

struct CmsDeleter {
    void operator()(CMS_ContentInfo* cms) const
    {
        CMS_ContentInfo_free(cms);
    }
};
using CmsPtr = std::unique_ptr<CMS_ContentInfo, CmsDeleter>;

BioPtr makeMemoryBio()
{
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new failed");
    }
    return bio;
}

BioPtr makeInputBio(const Bytes& data)
{
    BioPtr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new_mem_buf failed");
    }
    return bio;
}

BioPtr makeReadFileBio(const std::filesystem::path& path)
{
    BioPtr bio(BIO_new_file(path.string().c_str(), "rb"));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new_file (read) failed: " + path.string());
    }
    return bio;
}

BioPtr makeWriteFileBio(const std::filesystem::path& path)
{
    BioPtr bio(BIO_new_file(path.string().c_str(), "wb"));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new_file (write) failed: " + path.string());
    }
    return bio;
}

Bytes bioToBytes(BIO* const bio)
{
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    if (size < 0 || data == nullptr) {
        throw std::runtime_error("BIO_get_mem_data failed");
    }
    return Bytes(data, data + size);
}

void addPasswordRecipient(CMS_ContentInfo* const cms, const std::string& password)
{
    unsigned char* const copy
        = static_cast<unsigned char*>(OPENSSL_memdup(password.data(), password.size()));
    if (copy == nullptr) {
        throw std::runtime_error("OPENSSL_memdup failed");
    }
    if (CMS_add0_recipient_password(
            cms, -1, NID_undef, NID_undef, copy, static_cast<int>(password.size()), nullptr)
        == nullptr) {
        OPENSSL_free(copy);
        throw std::runtime_error("CMS_add0_recipient_password failed");
    }
}

void unsealWithPasswordBio(BIO* const input, BIO* const output, const std::string& password)
{
    const CmsPtr cms(d2i_CMS_bio(input, nullptr));
    if (cms == nullptr) {
        throw std::runtime_error("d2i_CMS_bio failed");
    }
    if (CMS_decrypt_set1_password(cms.get(),
            reinterpret_cast<unsigned char*>(const_cast<char*>(password.data())),
            static_cast<int>(password.size()))
        != 1) {
        throw std::runtime_error("CMS_decrypt_set1_password failed");
    }
    if (CMS_decrypt(cms.get(), nullptr, nullptr, nullptr, output, CMS_BINARY) != 1) {
        throw std::runtime_error("CMS_decrypt failed (wrong password?)");
    }
}

}  // namespace

namespace bazarish::cms {

Bytes sealWithPassword(const Bytes& plaintext, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeInputBio(plaintext);
    const CmsPtr cms(
        CMS_encrypt(nullptr, input.get(), EVP_aes_256_cbc(), CMS_BINARY | CMS_PARTIAL));
    if (cms == nullptr) {
        throw std::runtime_error("CMS_encrypt failed");
    }
    addPasswordRecipient(cms.get(), password);
    if (CMS_final(cms.get(), input.get(), nullptr, CMS_BINARY) != 1) {
        throw std::runtime_error("CMS_final failed");
    }

    const BioPtr output = makeMemoryBio();
    if (i2d_CMS_bio(output.get(), cms.get()) != 1) {
        throw std::runtime_error("i2d_CMS_bio failed");
    }
    return bioToBytes(output.get());
}

void sealWithPasswordToFile(const std::filesystem::path& inPath,
    const std::filesystem::path& outPath, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeReadFileBio(inPath);
    const BioPtr output = makeWriteFileBio(outPath);
    const CmsPtr cms(CMS_encrypt(
        nullptr, input.get(), EVP_aes_256_cbc(), CMS_BINARY | CMS_PARTIAL | CMS_STREAM));
    if (cms == nullptr) {
        throw std::runtime_error("CMS_encrypt failed");
    }
    addPasswordRecipient(cms.get(), password);
    if (i2d_CMS_bio_stream(output.get(), cms.get(), input.get(), CMS_BINARY | CMS_STREAM) != 1) {
        throw std::runtime_error("i2d_CMS_bio_stream failed");
    }
}

Bytes unsealWithPassword(const Bytes& der, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeInputBio(der);
    const BioPtr output = makeMemoryBio();
    unsealWithPasswordBio(input.get(), output.get(), password);
    return bioToBytes(output.get());
}

void unsealWithPasswordToFile(const std::filesystem::path& derPath,
    const std::filesystem::path& outPath, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeReadFileBio(derPath);
    const BioPtr output = makeWriteFileBio(outPath);
    unsealWithPasswordBio(input.get(), output.get(), password);
    if (BIO_flush(output.get()) != 1) {
        throw std::runtime_error("BIO_flush failed");
    }
}

}  // namespace bazarish::cms
