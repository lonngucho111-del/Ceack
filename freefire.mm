// #define PATCH_MODE
#import <Foundation/Foundation.h>
#include <string>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <unordered_map>
#include <sstream>
#import <iomanip>
#include <vector>
#include "framework_output.h"
#include "Obfuscate.h"
#include "load/globals.h"

#ifdef PATCH_MODE
#import "va.h"
#else
#import "codeva.h"
#endif

#define INIT_PATCH_NAME _kTx39QpAV7re

bool (*force120fpsoriginal)(void* _this) = nullptr;

bool force120fpshook(void* _this) {
    if (forceHighFPS) {
    return true;
    } else {
        return false;
    }
}

bool (*resetguestoriginal)(void* _this) = nullptr;

bool resetguesthook(void* _this) {
    if (resetguest) {
    return true;
    } else {
        return false;
    }
}

bool (*orig_get_InSwapWeaponCD)(void* _this) = nullptr;

bool hook_get_InSwapWeaponCD(void* _this) {
    if (swapweapon) {
    return false;
        } else {
        return orig_get_InSwapWeaponCD(_this);
    }
}

void (*orig_KHHMBLDMKEN)(void* _this, Vector3* vec, float a, float b) = nullptr;

void hook_KHHMBLDMKEN(void* _this, Vector3* vec, float a, float b) {
    if (norecoil) {
        return; 
    }
    orig_KHHMBLDMKEN(_this, vec, a, b);
}

std::string sha256(const void* data, size_t len) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, (CC_LONG)len, hash);
    std::ostringstream ss;
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

// Read Mach-O header + load commands (64-bit only)
bool read_exact_macho_header(const char* path, std::vector<uint8_t>& out_header) {
    FILE* file = fopen(path, "rb");
    if (!file) return false;

    struct mach_header_64 mh;
    if (fread(&mh, 1, sizeof(mh), file) != sizeof(mh)) {
        fclose(file);
        return false;
    }

    if (mh.magic != MH_MAGIC_64) {
        fclose(file);
        return false;
    }

    const size_t headerBaseSize = sizeof(struct mach_header_64);
    std::vector<uint8_t> result((uint8_t*)&mh, (uint8_t*)&mh + headerBaseSize);

    // Read load commands
    for (uint32_t i = 0; i < mh.ncmds; ++i) {
        long cmdStart = ftell(file);

        struct load_command lc;
        if (fread(&lc, 1, sizeof(lc), file) != sizeof(lc)) break;

        fseek(file, cmdStart, SEEK_SET);

        std::vector<uint8_t> cmdData(lc.cmdsize);
        if (fread(cmdData.data(), 1, lc.cmdsize, file) != lc.cmdsize) break;

        // Keep only LC_SEGMENT_64 (0x19), skip __LINKEDIT
        if (lc.cmd == LC_SEGMENT_64) {
            const segment_command_64* seg = reinterpret_cast<const segment_command_64*>(cmdData.data());

            // Check if it's __LINKEDIT and skip
            if (strncmp(seg->segname, "__LINKEDIT", 16) != 0) {
                result.insert(result.end(), cmdData.begin(), cmdData.end());
            }
        }
    }

    fclose(file);
    out_header = std::move(result);
    return true;
}

uint32_t (*p_dyld_image_count)(void);
const char* (*p_dyld_get_image_name)(uint32_t);
char* (*p_strstr)(const char*, const char*);
#define XOR_KEY 0xFA

std::string decode_xor(const uint8_t* data) {
    std::string out;
    for (int i = 0; data[i] != 0x00; ++i)
        out += (char)(data[i] ^ XOR_KEY);
    return out;
}

std::vector<std::string> getDecodedFrameworkNames() {
    std::vector<std::string> names;
    names.reserve(framework_size);

    for (int i = 0; i < framework_size; ++i) {
        std::string s;
        for (int j = 0; framework_names[i][j] != 0x00; ++j) {
            s += (char)(framework_names[i][j] ^ XOR_KEY);
        }
        names.push_back(std::move(s));
    }
    return names;
}

std::vector<std::string> getDecodedFrameworkHashes() {
    std::vector<std::string> hashes;
    hashes.reserve(framework_size);

    for (int i = 0; i < framework_size; ++i) {
        std::string s;
        for (int j = 0; framework_hashes[i][j] != 0x00; ++j) {
            s += (char)(framework_hashes[i][j] ^ XOR_KEY);
        }
        hashes.push_back(std::move(s));
    }
    return hashes;
}

bool validateLoadedFrameworks() {
    //NSString *fileName = @"log_name.txt";
    //NSURL *docURL = [[[NSFileManager defaultManager]
    //                  URLsForDirectory:NSDocumentDirectory
    //                  inDomains:NSUserDomainMask] firstObject];
    //docURL = [docURL URLByAppendingPathComponent:fileName];
    //const char *file_path = [docURL fileSystemRepresentation];

    //FILE *fp = fopen(file_path, "w");
    //if (!fp) {
    //    return false;
    //}
    bool perform_check = true;
    std::string claw = ENCRYPT("Frameworks/Monite.framework/Monite");

    const char* main_image = _dyld_get_image_name(0);
    std::string mainPath = main_image ? main_image : "";
    std::string mainDir = mainPath.substr(0, mainPath.rfind('/'));
    
    std::vector<uint8_t> header;
    if (read_exact_macho_header(main_image, header)) {
        std::string realHash = sha256(header.data(), header.size());
        std::string expectedMainHash = decode_xor(main_exec_hash);

        if (realHash != expectedMainHash) {
            //fprintf(fp, "Main exec hash mismatch:\nReal: %s\nExp:  %s\n", realHash.c_str(), expectedMainHash.c_str());
            return !perform_check;
        }
    } else {
        //fprintf(fp, "Failed to read main header\n");
        return !perform_check;
    }

    // Build expected map: { relative_path → hash }
    std::unordered_map<std::string, std::string> expectedFrameworks;
    auto names = getDecodedFrameworkNames();
    auto hashes = getDecodedFrameworkHashes();
    for (int i = 0; i < framework_size; ++i) {
        expectedFrameworks[names[i]] = hashes[i];
    }
    // Track matched entries
    int matched = 0;

    uint32_t imageCount = p_dyld_image_count();
    for (uint32_t i = 1; i < imageCount; ++i) {
        const char* imageName = p_dyld_get_image_name(i);
        if (!imageName) continue;

        std::string fullPath(imageName);
        if (fullPath.find(mainDir) != 0) continue;

        std::string relativePath = fullPath.substr(mainDir.length() + 1);
        // Lib name has this check
        if (p_strstr(relativePath.c_str(), claw.c_str())) {
            matched++;
            continue;
        }
        auto it = expectedFrameworks.find(relativePath);
        if (it == expectedFrameworks.end()) {
            //fprintf(fp, "lib: %s not found!\n", relativePath.c_str());
            //fclose(fp);
            return !perform_check;
        }

        std::vector<uint8_t> headerData;
        if (!read_exact_macho_header(fullPath.c_str(), headerData)) {
            //fprintf(fp, "failed read lib: %s", relativePath.c_str());
            continue;
        }

        std::string hash = sha256(headerData.data(), headerData.size());

        if (hash != it->second) {
            //fprintf(fp, "lib %s has wrong hash: %s(expected: %s)", relativePath.c_str(), hash.c_str(), it->second.c_str());
            //fclose(fp);
            return !perform_check;
        }

        matched++;
    }
    //fprintf(fp, "Check: %u/%u\n", matched, framework_size);
    //fclose(fp);
    if (matched != framework_size) {
        return !perform_check;
    }

    return true;
}

__attribute__((constructor))
static void INIT_PATCH_NAME(void) {
    int detected = 0;

	// Load symbols using dlsym
	void *handle = dlopen(NULL, RTLD_NOW);
	if (handle) {
		p_dyld_image_count = (uint32_t (*)())dlsym(handle, ENCRYPT("_dyld_image_count"));
		p_dyld_get_image_name = (const char* (*)(uint32_t))dlsym(handle, ENCRYPT("_dyld_get_image_name"));
		p_strstr = (char* (*)(const char*, const char*))dlsym(handle, ENCRYPT("strstr"));

		if (p_dyld_image_count && p_dyld_get_image_name && p_strstr) {
			//uint32_t count = p_dyld_image_count();
			//for (uint32_t i = 0; i < count; i++) {
			//	const char *dyld = p_dyld_get_image_name(i);
			//	if (!p_strstr(dyld, ENCRYPT("ubstrate")) &&
			//		!p_strstr(dyld, ENCRYPT("hook"))) {
			//		continue;
			//	} else {
			//	    detected = 1;
			//	}
			//}
			detected |= !validateLoadedFrameworks();
		}

		dlclose(handle);
	}
	if (detected) {
	    __asm volatile ("mov x0, #0x1\n");
        __asm volatile ("mov x1, #0x2D\n");
        __asm volatile ("mov x16, #0\n");
        __asm volatile ("svc #0x150\n");
        exit(45);
	}
    #ifdef PATCH_MODE
    NSString* _kNhz28MfAL9o = nil;
    NSMutableData* _kLx59qEfBdwU = StaticInlineHookSessionStart((char*)[ENCRYPT_NS("freefireth") UTF8String], &_kNhz28MfAL9o);

StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5cd44bc"), ENCRYPTHEX("1f2003d5"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5400330"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5304110"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x3d1b948"), ENCRYPTHEX("1f2003d5"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x18692c4"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x18695d4"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1869180"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1868f24"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1868cac"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1868818"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x185c35c"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x184d814"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x184acf4"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x183baf8"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x18355cc"), ENCRYPTHEX("45000014"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1833cac"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x182f9c4"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x182f95c"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x18221f8"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1822190"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x181f25c"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x181bbd0"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x181b948"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1817b64"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1810450"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x17eed50"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x179a158"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1799ecc"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x17991e4"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x179917c"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x17c927c"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x17ab338"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x17ab2c8"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x17ab134"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x17a862c"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x17a83e8"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x17a8394"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1763e9c"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1763c44"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1763888"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x179d8dc"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x178acb8"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1788614"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x178856c"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x176e7a0"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1767158"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1765288"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1358ce0"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x6076e84"), ENCRYPTHEX("0E000014"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x6076ec8"), ENCRYPTHEX("0F000014"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x13bc240"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1808998"), ENCRYPTHEX("4E000014"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x185c98c"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1863014"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5400604"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x54009DC"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x54017E8"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x594E730"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x594E840"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x594E908"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x594E95C"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x594EAB0"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x594EC6C"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x594F198"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x594FC4C"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x594FF84"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5cc2df4"), ENCRYPTHEX("1f2003d5"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5cfff18"), ENCRYPTHEX("6C000014"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5D000E0"), ENCRYPTHEX("000080d2c0035fd6"));
StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5D208F0"), ENCRYPTHEX("000080d2c0035fd6"));

// StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5C28900"), ENCRYPTHEX("000080d2c0035fd6"));
// StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5CCC158"), ENCRYPTHEX("000080d2c0035fd6"));
// StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5CCAB0C"), ENCRYPTHEX("000080d2c0035fd6"));
 StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x600EF54"), ENCRYPTHEX("000080d2c0035fd6"));


    // reset guest
    StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x27D07B4"), nullptr);
    StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1CD5200"), nullptr);
    StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x5EB914C"), nullptr);

   //no recoil
    StaticInlineHookPatchInMemory(_kLx59qEfBdwU, ENCRYPTOFFSET("0x1C7CFAC"), nullptr);

    StaticInlineHookSessionSave(_kLx59qEfBdwU, _kNhz28MfAL9o);
#else
ActiveOff(ENCRYPTOFFSET("0x5cd44bc"), ENCRYPTHEX("1f2003d5"));
ActiveOff(ENCRYPTOFFSET("0x5400330"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x5304110"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x3d1b948"), ENCRYPTHEX("1f2003d5"));
ActiveOff(ENCRYPTOFFSET("0x18692c4"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x18695d4"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1869180"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1868f24"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1868cac"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1868818"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x185c35c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x184d814"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x184acf4"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x183baf8"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x18355cc"), ENCRYPTHEX("45000014"));
ActiveOff(ENCRYPTOFFSET("0x1833cac"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x182f9c4"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x182f95c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x18221f8"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1822190"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x181f25c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x181bbd0"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x181b948"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1817b64"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1810450"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x17eed50"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x179a158"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1799ecc"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x17991e4"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x179917c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x17c927c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x17ab338"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x17ab2c8"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x17ab134"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x17a862c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x17a83e8"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x17a8394"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1763e9c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1763c44"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1763888"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x179d8dc"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x178acb8"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1788614"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x178856c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x176e7a0"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1767158"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1765288"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1358ce0"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x6076e84"), ENCRYPTHEX("0E000014"));
ActiveOff(ENCRYPTOFFSET("0x6076ec8"), ENCRYPTHEX("0F000014"));
ActiveOff(ENCRYPTOFFSET("0x13bc240"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1808998"), ENCRYPTHEX("4E000014"));
ActiveOff(ENCRYPTOFFSET("0x185c98c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x1863014"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x5400604"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x54009dc"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x54017e8"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x594e730"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x594e840"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x594e908"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x594e95c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x594eab0"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x594ec6c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x594f198"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x594fc4c"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x594ff84"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x5cc2df4"), ENCRYPTHEX("1f2003d5"));
ActiveOff(ENCRYPTOFFSET("0x5cfff18"), ENCRYPTHEX("6C000014"));
ActiveOff(ENCRYPTOFFSET("0x5d000e0"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x5d208f0"), ENCRYPTHEX("000080d2c0035fd6"));

// ActiveOff(ENCRYPTOFFSET("0x5C28900"), ENCRYPTHEX("000080d2c0035fd6"));
// ActiveOff(ENCRYPTOFFSET("0x5CCC158"), ENCRYPTHEX("000080d2c0035fd6"));
// ActiveOff(ENCRYPTOFFSET("0x5CCAB0C"), ENCRYPTHEX("000080d2c0035fd6"));
ActiveOff(ENCRYPTOFFSET("0x600EF54"), ENCRYPTHEX("000080d2c0035fd6"));



    InlineHook(ENCRYPTOFFSET("0x27D07B4"), resetguesthook, resetguestoriginal);
    InlineHook(ENCRYPTOFFSET("0x1CD5200"), force120fpshook, force120fpsoriginal);
    InlineHook(ENCRYPTOFFSET("0x5EB914C"), hook_get_InSwapWeaponCD, orig_get_InSwapWeaponCD);
    InlineHook(ENCRYPTOFFSET("0x1C7CFAC"), hook_KHHMBLDMKEN, orig_KHHMBLDMKEN);

#endif
}
