// Bazarish project (c) 2026
#include "bazarish/Cms.hpp"

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include <array>
#include <cstddef>
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

struct BioChainDeleter {
    void operator()(BIO* bio) const
    {
        BIO_free_all(bio);
    }
};
using BioChainPtr = std::unique_ptr<BIO, BioChainDeleter>;

constexpr std::size_t kStreamChunkBytes = 64 * 1024;

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

Bytes sealWithPasswordDetached(const std::filesystem::path& inPath,
    const std::filesystem::path& contentPath, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeReadFileBio(inPath);
    BioPtr content = makeWriteFileBio(contentPath);
    const CmsPtr cms(CMS_encrypt(nullptr, nullptr, EVP_aes_256_cbc(),
        CMS_BINARY | CMS_PARTIAL | CMS_DETACHED | CMS_STREAM));
    if (cms == nullptr) {
        throw std::runtime_error("CMS_encrypt failed");
    }
    addPasswordRecipient(cms.get(), password);
    const BioChainPtr chain(CMS_dataInit(cms.get(), content.get()));
    if (chain == nullptr) {
        throw std::runtime_error("CMS_dataInit failed");
    }
    content.release();
    std::array<unsigned char, kStreamChunkBytes> buffer{};
    for (;;) {
        const int got = BIO_read(input.get(), buffer.data(), static_cast<int>(buffer.size()));
        if (got < 0) {
            throw std::runtime_error("reading " + inPath.string() + " failed");
        }
        if (got == 0) {
            break;
        }
        if (BIO_write(chain.get(), buffer.data(), got) != got) {
            throw std::runtime_error("writing " + contentPath.string() + " failed");
        }
    }
    if (BIO_flush(chain.get()) != 1) {
        throw std::runtime_error("BIO_flush failed");
    }
    if (CMS_dataFinal(cms.get(), chain.get()) != 1) {
        throw std::runtime_error("CMS_dataFinal failed");
    }
    if (CMS_set_detached(cms.get(), 1) != 1) {
        throw std::runtime_error("CMS_set_detached failed");
    }
    const BioPtr header = makeMemoryBio();
    if (i2d_CMS_bio(header.get(), cms.get()) != 1) {
        throw std::runtime_error("i2d_CMS_bio failed");
    }
    return bioToBytes(header.get());
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

void unsealWithPasswordDetached(const Bytes& header, const std::filesystem::path& contentPath,
    const std::string& password, const PlainWriteFn& write)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr headerBio = makeInputBio(header);
    const CmsPtr cms(d2i_CMS_bio(headerBio.get(), nullptr));
    if (cms == nullptr) {
        throw std::runtime_error("d2i_CMS_bio failed");
    }
    if (CMS_is_detached(cms.get()) != 1) {
        throw std::runtime_error("the envelope carries its content");
    }
    if (CMS_decrypt_set1_password(cms.get(),
            reinterpret_cast<unsigned char*>(const_cast<char*>(password.data())),
            static_cast<int>(password.size()))
        != 1) {
        throw std::runtime_error("CMS_decrypt_set1_password failed");
    }
    BioPtr content = makeReadFileBio(contentPath);
    const BioChainPtr chain(CMS_dataInit(cms.get(), content.get()));
    if (chain == nullptr) {
        throw std::runtime_error("CMS_dataInit failed");
    }
    content.release();
    std::array<unsigned char, kStreamChunkBytes> buffer{};
    for (;;) {
        const int got = BIO_read(chain.get(), buffer.data(), static_cast<int>(buffer.size()));
        if (got < 0) {
            throw std::runtime_error("reading " + contentPath.string() + " failed");
        }
        if (got == 0) {
            break;
        }
        write(buffer.data(), static_cast<std::size_t>(got));
    }
    // The padding of the last block is checked only once the content has run out.
    if (BIO_get_cipher_status(chain.get()) != 1) {
        throw std::runtime_error("the content does not decrypt (wrong password?)");
    }
}

}  // namespace bazarish::cms
