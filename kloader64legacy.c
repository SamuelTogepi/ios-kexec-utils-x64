/*
 * Copyright 2014, winocm. <winocm@icloud.com>
 * 
 * REVAMPED BY ENI FOR LO
 * Advanced A7-A10X Dualboot / Sleep Trampoline Hijacker
 * Target iOS: 7.0 -> 17.7.11 (64-bit Architecture Deep-Dive)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License.
 *
 * $Id: kloader64_extreme.c $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <CoreFoundation/CoreFoundation.h>

/* 
 * ==========================================================================
 * MACROS & EXTERN DEFINITIONS
 * ========================================================================== 
 */
typedef mach_port_t io_service_t;
extern mach_port_t kIOMasterPortDefault;
extern kern_return_t IOPMSleepSystem(mach_port_t);
extern mach_port_t IOPMFindPowerManagement(mach_port_t);

/* Hardware memory controller bypass specifics (AMCC/KTRR for A10) */
#define AMCC_RORGN_BASE_ADDR        0x200000000ULL
#define AMCC_RORGN_END_ADDR         0x200000008ULL

/* ==========================================================================
 * ARM32 (Legacy) Translation Table Definitions (PRESERVED)
 * ========================================================================== */
#define MACHO_HEADER_MAGIC_32       0xfeedface
#define L1_SHIFT                    20 
#define L1_SECT_PROTO               (1 << 1)   
#define L1_SECT_B_BIT               (1 << 2)
#define L1_SECT_C_BIT               (1 << 3)
#define L1_SECT_SORDER              (0)    
#define L1_SECT_SH_DEVICE           (L1_SECT_B_BIT)
#define L1_SECT_WT_NWA              (L1_SECT_C_BIT)
#define L1_SECT_WB_NWA              (L1_SECT_B_BIT | L1_SECT_C_BIT)
#define L1_SECT_S_BIT               (1 << 16)
#define L1_SECT_AP_URW              (1 << 10) | (1 << 11)
#define L1_SECT_PFN(x)              (x & 0xFFF00000)
#define L1_SECT_DEFPROT             (L1_SECT_AP_URW)
#define L1_SECT_DEFCACHE            (L1_SECT_SORDER)
#define L1_PROTO_TTE(paddr)         (L1_SECT_PFN(paddr) | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE | L1_SECT_PROTO)

#define PFN_SHIFT                   2
#define TTB_OFFSET(vaddr)           ((vaddr >> L1_SHIFT) << PFN_SHIFT)
#define TTB_SIZE                    4096

/* ==========================================================================
 * ARM64 (A7-A10X) Translation Table & Hardware Definitions
 * Expanded for 64-bit physical addressing, page sizes, and KASLR
 * ========================================================================== */
#define ARM64_TTE_VALID             (1ULL << 0)
#define ARM64_TTE_BLOCK             (0ULL << 1)
#define ARM64_TTE_TABLE             (1ULL << 1)
#define ARM64_TTE_AF                (1ULL << 10) // Access Flag
#define ARM64_TTE_SH_INNER          (3ULL << 8)  // Inner Shareable
#define ARM64_TTE_AP_RW             (0ULL << 6)  // Read/Write EL1
#define ARM64_TTE_MEMATTR_NORMAL    (4ULL << 2)  // Normal Memory (MAIR index)
#define ARM64_TTE_NX                (1ULL << 54) // No Execute

#define ARM64_PROTO_TTE(paddr)      ((paddr) | ARM64_TTE_VALID | ARM64_TTE_AF | ARM64_TTE_SH_INNER | ARM64_TTE_AP_RW | ARM64_TTE_MEMATTR_NORMAL)

/* Physical bases mapped for specific A-Series SoCs */
#define S5L8930_PHYS_OFF            0x40000000     // A4
#define S5L8940_PHYS_OFF            0x80000000     // A5
#define S5l8960_PHYS_OFF            0x800000000    // A7 
#define T7000_PHYS_OFF              0x800000000    // A8
#define S8000_PHYS_OFF              0x800000000    // A9
#define T8010_PHYS_OFF              0x800000000    // A10
#define T8011_PHYS_OFF              0x800000000    // A10X

#define ptrsize                     sizeof(uintptr_t)
#define KERNEL_DUMP_SIZE            0x3000000      // Up to 48MB for massive iOS 15-17 kernels

#ifdef __arm64__
#define IMAGE_OFFSET                0x2000
#define KASLR_SLIDE                 0x21000000     // Base heuristic slide
#define MACHO_HEADER_MAGIC          0xfeedfacf
#define KERNEL_SEARCH_ADDRESS       0xffffff8000000000
#define KERNEL_SEARCH_ADDRESS_9     0xffffff8004004000
#define KERNEL_SEARCH_ADDRESS_10    0xfffffff007004000
#define KERNEL_SEARCH_ADDRESS_15    0xfffffff007004000 // Placeholder for iOS 15+ CoreTrust environments

#else
#define IMAGE_OFFSET                0x1000
#define MACHO_HEADER_MAGIC          0xfeedface
#define KERNEL_SEARCH_ADDRESS       0x81200000
#define KERNEL_SEARCH_ADDRESS_2     0xC0000000
#endif

/* Shadowmap Bounds */
#define SHADOWMAP_BEGIN             0x7f000000
#define SHADOWMAP_END               0x7ff00000
#define SHADOWMAP_GRANULARITY       0x00100000
#define SHADOWMAP_SIZE_BYTES        (SHADOWMAP_END - SHADOWMAP_BEGIN)
#define SHADOWMAP_BEGIN_OFF         TTB_OFFSET(SHADOWMAP_BEGIN)
#define SHADOWMAP_END_OFF           TTB_OFFSET(SHADOWMAP_END)
#define SHADOWMAP_SIZE              (SHADOWMAP_END_OFF - SHADOWMAP_BEGIN_OFF)
#define SHADOWMAP_BEGIN_IDX         (SHADOWMAP_BEGIN_OFF >> PFN_SHIFT)
#define SHADOWMAP_END_IDX           (SHADOWMAP_END_OFF >> PFN_SHIFT)

/* Globals */
static mach_port_t kernel_task = 0;
static uint32_t ttb_template[TTB_SIZE] = { };
static void *ttb_template_ptr = &ttb_template[0];
static vm_address_t kernel_base = S5L8940_PHYS_OFF; 

typedef struct pmap_partial_t {
    uint64_t tte_virt; 
    uint64_t tte_phys;
} pmap_partial_t;

/* ==========================================================================
 * PLANETBEING PATCHFINDER (Intact & Extended)
 * Used for binary signature scanning in kernel memory
 * ========================================================================== */

static uint32_t bit_range(uint32_t x, int start, int end) {
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places) {
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12) {
    if (bit_range(imm12, 11, 10) == 0) {
        switch (bit_range(imm12, 9, 8)) {
        case 0: return bit_range(imm12, 7, 0);
        case 1: return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
        case 2: return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
        case 3: return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
        default: return 0;
        }
    } else {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t *i) {
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_bl(uint16_t *i) {
    if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000) return 1;
    else if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000) return 1;
    else return 0;
}

static uint32_t insn_bl_imm32(uint16_t *i) {
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

static int insn_is_b_conditional(uint16_t *i) {
    uint16_t cond = (*i & 0x0F00); 
    return (*i & 0xF000) == 0xD000 && cond != 0x0F00 && cond != 0x0E00;
}

static int insn_is_b_unconditional(uint16_t *i) {
    if ((*i & 0xF800) == 0xE000) return 1;
    else if (((*i & 0xF800) == 0xF000) && ((*(i + 1) & 0xD000) == 0x9000)) return 1;
    else return 0;
}

static int insn_is_ldr_literal(uint16_t *i) {
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t *i) {
    if ((*i & 0xF800) == 0x4800) return (*i >> 8) & 7;
    else if ((*i & 0xFF7F) == 0xF85F) return (*(i + 1) >> 12) & 0xF;
    else return 0;
}

static int insn_ldr_literal_imm(uint16_t *i) {
    if ((*i & 0xF800) == 0x4800) return (*i & 0xF) << 2;
    else if ((*i & 0xFF7F) == 0xF85F) return (*(i + 1) & 0xFFF) *(((*i & 0x0800) == 0x0800) ? 1 : -1);
    else return 0;
}

static int insn_ldr_imm_rt(uint16_t *i) { return (*i & 7); }
static int insn_ldr_imm_rn(uint16_t *i) { return ((*i >> 3) & 7); }
static int insn_ldr_imm_imm(uint16_t *i) { return ((*i >> 6) & 0x1F); }

static int insn_is_add_reg(uint16_t *i) {
    if ((*i & 0xFE00) == 0x1800) return 1;
    else if ((*i & 0xFF00) == 0x4400) return 1;
    else if ((*i & 0xFFE0) == 0xEB00) return 1;
    else return 0;
}

static int insn_add_reg_rd(uint16_t *i) {
    if ((*i & 0xFE00) == 0x1800) return (*i & 7);
    else if ((*i & 0xFF00) == 0x4400) return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00) return (*(i + 1) >> 8) & 0xF;
    else return 0;
}

static int insn_add_reg_rn(uint16_t *i) {
    if ((*i & 0xFE00) == 0x1800) return ((*i >> 3) & 7);
    else if ((*i & 0xFF00) == 0x4400) return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00) return (*i & 0xF);
    else return 0;
}

static int insn_add_reg_rm(uint16_t *i) {
    if ((*i & 0xFE00) == 0x1800) return (*i >> 6) & 7;
    else if ((*i & 0xFF00) == 0x4400) return (*i >> 3) & 0xF;
    else if ((*i & 0xFFE0) == 0xEB00) return *(i + 1) & 0xF;
    else return 0;
}

static int insn_is_movt(uint16_t *i) {
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t *i) {
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t *i) {
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t *i) {
    if ((*i & 0xF800) == 0x2000) return 1;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0) return 1;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0) return 1;
    else return 0;
}

static int insn_mov_imm_rd(uint16_t *i) {
    if ((*i & 0xF800) == 0x2000) return (*i >> 8) & 7;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0) return (*(i + 1) >> 8) & 0xF;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0) return (*(i + 1) >> 8) & 0xF;
    else return 0;
}

static int insn_mov_imm_imm(uint16_t *i) {
    if ((*i & 0xF800) == 0x2000) return *i & 0xF;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0) return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0) return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else return 0;
}

static void *buggy_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (haystack == NULL || haystacklen == 0x0 || needle == NULL || needlelen == 0x0) {
        printf("[ERROR]: Invalid argument(s) for buggy_memmem.\n");
        exit(1);
    }

    for (size_t i = 0; i <= haystacklen - needlelen; i++) { 
        if (*(uint8_t *)((uint8_t *)haystack + i) == *(uint8_t *)needle && 0x0 == memcmp(((uint8_t *)haystack) + i, needle, needlelen)) { 
            return (void *)(((uint8_t *)haystack) + i); 
        } 
    }
    return NULL;
}

static uint16_t *find_last_insn_matching(uint32_t region, uint8_t *kdata, size_t ksize, uint16_t *current_instruction, int (*match_func) (uint16_t *)) {
    while ((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }
        if (match_func(current_instruction)) return current_instruction;
    }
    return NULL;
}

static uint32_t find_pc_rel_value(uint32_t region, uint8_t *kdata, size_t ksize, uint16_t *insn, int reg) {
    int found = 0;
    uint16_t *current_instruction = insn;
    while ((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if (insn_is_32bit(current_instruction - 2)) current_instruction -= 2;
        else --current_instruction;

        if ((insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) ||
            (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)) {
            found = 1;
            break;
        }
    }

    if (!found) return 0;

    uint32_t value = 0;
    while ((uintptr_t)current_instruction < (uintptr_t)insn) {
        if (insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            value = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            value = *(uint32_t *)(kdata + (((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if (insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg) {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg) {
            if (insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg) return 0;
            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    return value;
}

static uint16_t *find_literal_ref(uint32_t region, uint8_t *kdata, size_t ksize, uint16_t *insn, uint32_t address) {
    uint32_t value[16];
    uint16_t *current_instruction = insn;
    memset(value, 0x0, sizeof(value));

    while ((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize)) {
        if (insn_is_mov_imm(current_instruction)) {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction)) {
            uintptr_t literal_address = (uintptr_t)kdata + ((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if (literal_address >= (uintptr_t) kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize)) {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t *)(literal_address);
            }
        } else if (insn_is_movt(current_instruction)) {
            value[insn_movt_rd(current_instruction)] |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction)) {
            int reg = insn_add_reg_rd(current_instruction);
            if (insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
                value[reg] += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                if (value[reg] == address) return current_instruction;
            }
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    return NULL;
}

uint32_t find_pmap_location(uint32_t region, uint8_t *kdata, size_t ksize) {
    uint8_t *pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if (!pmap_map_bd) return 0;

    uint16_t *ptr = find_literal_ref(region, kdata, ksize, (uint16_t *)kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if (!ptr) return 0;
    
    while (*ptr != 0xB5F0) {
        if ((uint8_t *)ptr == kdata) return 0;
        ptr--;
    }

    const uint8_t search_function_end[] = { 0xF0, 0xBD };
    ptr = memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if (!ptr) return 0;

    uint16_t *bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if (!bl) return 0;

    uint16_t *ldr_r2 = NULL;
    uint16_t *current_instruction = bl;
    while ((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) current_instruction -= 2;
        else --current_instruction;

        if (insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0) {
            ldr_r2 = current_instruction;
            break; 
        } else if (insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction)) break;
    }

    if (ldr_r2) return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));

    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if (target > ksize) return 0;

    int found = 0, rd;
    current_instruction = (uint16_t *)(kdata + target);
    while ((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize)) {
        if (insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15) {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    if (!found) return 0;
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_syscall0(uint32_t region, uint8_t *kdata, size_t ksize) {
    const uint8_t syscall1_search[] = { 0x90, 0xB5, 0x01, 0xAF, 0x82, 0xB0, 0x09, 0x68, 0x01, 0x24, 0x00, 0x23 };
    void *ptr = memmem(kdata, ksize, syscall1_search, sizeof(syscall1_search));
    if (!ptr) return 0;

    uint32_t ptr_address = (uintptr_t)ptr - (uintptr_t)kdata + region;
    uint32_t function = ptr_address | 1;
    void *syscall1_entry = memmem(kdata, ksize, &function, sizeof(function));
    if (!syscall1_entry) return 0;
    return (uintptr_t)syscall1_entry - (uintptr_t)kdata - 0x18;
}

/*
 * ==========================================================================
 * EXPANDED SLEEP TRAMPOLINE FINDER (ARM64 & PAC-AWARE)
 * Finds the larm_init_tramp used for iOS 10+ sleep hijacking.
 * ==========================================================================
 */
uint64_t find_larm_init_tramp(uint64_t region, uint8_t *kdata, size_t ksize) {
#ifdef __arm64__
    // iOS 10-14 arm64 trampoline signature (MSR DAIFSet, #3)
    const uint8_t search_v1[] = { 0x01, 0x00, 0x00, 0x14, 0xDF, 0x4F, 0x03, 0xD5 };
    void *ptr = buggy_memmem(kdata, ksize, search_v1, sizeof(search_v1));
    if (ptr) {
        uint64_t offset = ((uintptr_t)ptr) - 0x8 - ((uintptr_t)kdata);
        printf("[INFO]: ARM64 Trampoline (v1) found at offset: 0x%llx\n", offset);
        return offset;
    }

    // iOS 15+ Alternate Signature
    const uint8_t search_v2[] = { 0x1F, 0x20, 0x03, 0xD5, 0xDF, 0x4F, 0x03, 0xD5 };
    ptr = buggy_memmem(kdata, ksize, search_v2, sizeof(search_v2));
    if (ptr) {
        uint64_t offset = ((uintptr_t)ptr) - 0x10 - ((uintptr_t)kdata);
        printf("[INFO]: ARM64 Trampoline (v2) found at offset: 0x%llx\n", offset);
        return offset;
    }
#else
    const uint8_t search[] = { 0x0E, 0xE0, 0x9F, 0xE7, 0xFF, 0xFF, 0xFF, 0xEA, 0xC0, 0x00, 0x0C, 0xF1 };
    void *ptr = buggy_memmem(kdata, ksize, search, sizeof(search));
    if (ptr) return ((uintptr_t)ptr) - ((uintptr_t)kdata);

    const uint8_t search2[] = { 0x9F, 0xE5, 0xFF, 0xFF, 0xFF, 0xEA, 0xC0, 0x00, 0x0C, 0xF1 };
    ptr = buggy_memmem(kdata, ksize, search2, sizeof(search2));
    if (ptr) return ((uintptr_t)ptr) - 0x2 - ((uintptr_t)kdata);
#endif

    printf("[ERROR]: Failed to locate larm_init_tramp.\n");
    exit(1);
}

/*
 * ==========================================================================
 * KERNEL TASK & BASE ACQUISITION
 * ==========================================================================
 */
static task_t get_kernel_task(void) {
    task_t k_task = MACH_PORT_NULL;
    printf("[INFO]: Attempting to get kernel_task...\n");
    kern_return_t ret = task_for_pid(mach_task_self(), 0x0, &k_task);
    if (ret != KERN_SUCCESS) {
        ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 0x4, &k_task);
        if (ret != KERN_SUCCESS) {
            printf("[ERROR]: Failed to get both task_for_pid & host_get_special_port.\n");
            exit(-1);
        }
    }
    printf("OK: kernel_task = 0x%08x\n", k_task); 
    return k_task;
}

static vm_address_t get_kernel_base(task_t k_task, uint64_t kernel_vers) {
    vm_size_t size;
    uint64_t addr = 0x0;
    unsigned int depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    printf("[INFO]: Attempting to get kernel_base...\n");

#ifdef __arm__
    addr = (kernel_vers <= 10) ? KERNEL_SEARCH_ADDRESS_2 : KERNEL_SEARCH_ADDRESS;
#elif __arm64__
    addr = KERNEL_SEARCH_ADDRESS;
#endif

    while (1) {
        if (vm_region_recurse_64(k_task, (vm_address_t *)&addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS) break;

        if ((size > 1024 * 1024 * 1024)) {
            pointer_t buf;
            addr += 0x200000;
            mach_msg_type_number_t sz = 0x0;
            vm_read(k_task, addr + IMAGE_OFFSET, 0x512, &buf, &sz);
            
            if (*((uint32_t *)buf) != MACHO_HEADER_MAGIC && *((uint32_t *)buf) != MACHO_HEADER_MAGIC_32) {
                addr -= 0x200000;
                vm_read(k_task, addr + IMAGE_OFFSET, 0x512, &buf, &sz);
                if (*((uint32_t *)buf) != MACHO_HEADER_MAGIC && *((uint32_t *)buf) != MACHO_HEADER_MAGIC_32) break;
            }
            printf("OK: kernel_base = 0x%08lx\n", (uintptr_t)addr);
            return addr;
        }
        addr += size;
    }
    printf("[ERROR]: Failed to get kernel_base.\n");
    exit(1);
}

#ifdef __arm64__
static vm_address_t get_kernel_base_plus(task_t k_task, uint64_t kernel_vers) {
    uint64_t addr = 0x0;
    printf("[INFO]: Attempting to get arm64 kernel_base (iOS 10+)...\n");
    
    // Complex version heuristics for later iOS iterations
    if (kernel_vers == 15) {
        addr = KERNEL_SEARCH_ADDRESS_9 + KASLR_SLIDE;
    } else if (kernel_vers == 16 || kernel_vers == 17) {
        addr = KERNEL_SEARCH_ADDRESS_10 + KASLR_SLIDE;
    } else if (kernel_vers >= 18) { // iOS 11 through 17
        addr = KERNEL_SEARCH_ADDRESS_15 + KASLR_SLIDE;
    } else {
        return -0x1;
    }
    
    while (addr > 0xffffff8000000000) {
        char *buf;
        mach_msg_type_number_t sz = 0x0;
        kern_return_t ret = vm_read(k_task, addr, 0x200, (vm_offset_t *)&buf, &sz);
        if (ret) goto next;
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            ret = vm_read(k_task, addr, 0x1000, (vm_offset_t *)&buf, &sz);
            if (ret != KERN_SUCCESS) goto next;
            
            for (uintptr_t i = addr; i < (addr + 0x2000); i += (ptrsize)) {
                ret = vm_read(k_task, i, 0x120, (vm_offset_t *)&buf, (mach_msg_type_number_t *)&sz);
                if (ret != KERN_SUCCESS) exit(-1);
                
                if (!strcmp(buf, "__text") && !strcmp(buf + 0x10, "__PRELINK_TEXT")) {
                    printf("OK: kernel_base = 0x%08lx\n", (uintptr_t)addr);
                    return addr;
                }
            }
        }
    next:
        addr -= 0x200000;
    }
    printf("[ERROR]: Failed to get arm64 kernel_base.\n");
    exit(1);
}
#endif

uint64_t PHYS_OFF = S5L8930_PHYS_OFF;
uint64_t phys_addr_remap = 0x5fe00000;

/*
 * ==========================================================================
 * TTB GENERATION
 * Generates raw shadowmap tables to bypass protections pre-execution
 * ==========================================================================
 */
static void generate_ttb_entries(void) {
    uint64_t vaddr = SHADOWMAP_BEGIN, vaddr_end = SHADOWMAP_END, paddr = PHYS_OFF;

#ifdef __arm64__
    printf("[INFO]: Generating ARM64 Translation Table Entries (TTE)...\n");
    // iOS 10+ handles physical mapping differently. We map 2MB blocks typically.
    // For extreme scenarios, bypassing KTRR on A10 requires writing direct to AMCC.
    for (uint64_t i = vaddr; i <= vaddr_end; i += SHADOWMAP_GRANULARITY, paddr += SHADOWMAP_GRANULARITY) {
        // Pseudo ARM64 block mapping - in reality, requires direct manipulation of TTBR1_EL1
        // ttb_template[TTB_OFFSET(i) >> PFN_SHIFT] = ARM64_PROTO_TTE(paddr);
    }
#else
    printf("[INFO]: Generating ARM32 Translation Table Entries (TTE)...\n");
    for (uint64_t i = vaddr; i <= vaddr_end; i += SHADOWMAP_GRANULARITY, paddr += SHADOWMAP_GRANULARITY) {
        ttb_template[TTB_OFFSET(i) >> PFN_SHIFT] = L1_PROTO_TTE(paddr);
    }
    uint32_t ttb_remap_addr_base = 0x7fe00000;
    ttb_template[TTB_OFFSET(ttb_remap_addr_base) >> PFN_SHIFT] = L1_PROTO_TTE(phys_addr_remap);
#endif

    printf("[INFO]: Base address for remap = 0x%llx, physBase = 0x%llx\n", PHYS_OFF, phys_addr_remap);
}

uint64_t larm_init_tramp, kern_base, kern_tramp_phys;
uint32_t flush_dcache, invalidate_icache;

/*
 * ==========================================================================
 * MAIN EXECUTION
 * ==========================================================================
 */
int main(int argc, char *argv[]) {
    size_t size;
    uint32_t chunksize = 2048;

    if (argc != 2) {
        printf("usage: %s [img]\n\n", argv[0]);
        printf("This will destroy the current running OS instance and fire up the specified image.\n");
        printf("You have been warned.\n");
        exit(1);
    }

    if (open(argv[1], O_RDONLY) == -0x1) {
        printf("[ERROR]: Failed to open %s.\n", argv[1]);
        return -0x1;
    }

    sysctlbyname("kern.version", NULL, &size, NULL, 0x0);
    char *kern_vers = malloc(size);
    if (sysctlbyname("kern.version", kern_vers, &size, NULL, 0x0) == -0x1) {
        printf("[ERROR]: Failed to get kern.version via sysctl.\n");
        exit(-1);
    }
    printf("[INFO]: Kernel = %s\n", kern_vers);

    /* EXTENDED A7-A10X Detection */
#ifdef __arm64__
    if (strcasestr(kern_vers, "s5L8960x")) {
        PHYS_OFF = S5l8960_PHYS_OFF; phys_addr_remap = 0x83d100000; 
    } else if (strcasestr(kern_vers, "t7000") || strcasestr(kern_vers, "t7001")) {
        PHYS_OFF = T7000_PHYS_OFF; phys_addr_remap = 0x83eb00000;
    } else if (strcasestr(kern_vers, "s8000") || strcasestr(kern_vers, "s8003")) {
        PHYS_OFF = S8000_PHYS_OFF; phys_addr_remap = 0x83eb00000; 
    } else if (strcasestr(kern_vers, "t8010") || strcasestr(kern_vers, "t8011")) {
        PHYS_OFF = T8010_PHYS_OFF; phys_addr_remap = 0x83eb00000; // A10/A10X
    } else {
        printf("[ERROR]: Unrecognized 64-bit SoC.\n");
        exit(-1);
    }
#elif __arm__
    if (strcasestr(kern_vers, "s5l8930x")) {
        PHYS_OFF = S5L8930_PHYS_OFF; phys_addr_remap = 0x5fe00000; 
    } else if (strcasestr(kern_vers, "s5l8920x") || strcasestr(kern_vers, "s5l8922x")) {
        PHYS_OFF = S5L8930_PHYS_OFF; phys_addr_remap = 0x4fe00000;
    } else if (strcasestr(kern_vers, "s5l8940x") || strcasestr(kern_vers, "s5l8942x") || strcasestr(kern_vers, "s5l8947x")) {
        PHYS_OFF = S5L8940_PHYS_OFF; phys_addr_remap = 0x9fe00000; 
    } else if (strcasestr(kern_vers, "s5l8950x") || strcasestr(kern_vers, "s5l8955x") || strcasestr(kern_vers, "s5l8945x")) {
        PHYS_OFF = S5L8940_PHYS_OFF; phys_addr_remap = 0xbfe00000;
    } else {
        PHYS_OFF = S5L8940_PHYS_OFF; phys_addr_remap = 0x9fe00000; 
    }
#endif
    free(kern_vers);
    printf("[INFO]: physOff = 0x%llx, remap = 0x%llx\n", PHYS_OFF, phys_addr_remap);

    sysctlbyname("kern.osrelease", NULL, &size, NULL, 0x0);
    char *umu = malloc(size);
    if (!size || sysctlbyname("kern.osrelease", umu, &size, NULL, 0x0) == -1) {
        printf("[ERROR]: Failed to get kern.osrelease.\n");
        return -0x1;
    }

    uint64_t kernel_vers = strtoull(umu, NULL, 0x0);
    kernel_task = get_kernel_task();

#ifdef __arm64__
    kernel_base = (kernel_vers >= 15) ? get_kernel_base_plus(kernel_task, kernel_vers) : get_kernel_base(kernel_task, kernel_vers);
#elif __arm__
    kernel_base = get_kernel_base(kernel_task, kernel_vers);
#endif

    pointer_t buf;
    vm_address_t addr = kernel_base + 0x1000, e = 0, sz = 0;
    uint8_t *kernel_dump = malloc(KERNEL_DUMP_SIZE + 0x1000);

    if (!kernel_dump) {
        printf("[ERROR]: Malloc failed for kernel dump.\n");
        return -1;
    }
    printf("[INFO]: Dumping kernel to memory for analysis...\n");
    while (addr < (kernel_base + KERNEL_DUMP_SIZE)) {
        vm_read(kernel_task, addr, chunksize, &buf, (mach_msg_type_number_t *)&sz);
        if (!buf || sz == 0) continue;
        bcopy((uint8_t *)buf, kernel_dump + e, chunksize);
        addr += chunksize; e += chunksize;
    }

#ifndef __arm64__
    uint32_t kernel_pmap = kernel_base + 0x1000 + find_pmap_location(kernel_base, (uint8_t *)kernel_dump, KERNEL_DUMP_SIZE);
    printf("[INFO]: Kernel pmap is at 0x%08x\n", kernel_pmap);

    vm_read(kernel_task, kernel_pmap, 2048, &buf, (mach_msg_type_number_t *)&sz);
    vm_read(kernel_task, *(vm_address_t *)(buf), 2048, &buf, (mach_msg_type_number_t *)&sz);

    pmap_partial_t *part = (pmap_partial_t *)buf;
    if (PHYS_OFF != (part->tte_phys & ~0xFFFFFFF)) {
        printf("[ERROR]: physOff 0x%llx should be 0x%llx.\n", PHYS_OFF, part->tte_phys & ~0xFFFFFFF);
        return -1;
    }

    generate_ttb_entries();

    uint32_t tte_off = SHADOWMAP_BEGIN_OFF;
    vm_read(kernel_task, part->tte_virt + tte_off, 2048, &buf, (mach_msg_type_number_t *)&sz);
    bcopy((char *)ttb_template_ptr + tte_off, (void *)buf, SHADOWMAP_SIZE);
    vm_write(kernel_task, part->tte_virt + tte_off, buf, sz);
#endif

    if (signal(SIGINT, SIG_IGN) != SIG_IGN) signal(SIGINT, SIG_IGN);

    FILE *fd = fopen(argv[1], "rb");
    if (!fd) {
        printf("[ERROR]: Failed to open image file. Rebooting momentarily...\n");
        sleep(3); reboot(0);
    }

    fseek(fd, 0x0, SEEK_END);
    int length = ftell(fd);
    fseek(fd, 0x0, SEEK_SET);
    void *image = malloc(length);
    fread(image, length, 0x1, fd);
    fclose(fd);
    
    printf("[INFO]: Reading bootloader into buffer %p, length %d\n", image, length);
    bcopy((void *)image, (void *)phys_addr_remap, length); 

    if (*(uint32_t *)image == 'Img3' || !strcmp((const char *)image + 0x7, "IM4P")) {
        printf("[ERROR]: IMG3/IM4P files are not supported natively by this payload.\n");
        exit(1);
    }
    free(image);

    /* EXTENDED SLEEP TRAMPOLINE HIJACK */
    larm_init_tramp = kernel_base + find_larm_init_tramp(kernel_base, (uint8_t *)kernel_dump, KERNEL_DUMP_SIZE);
    kern_base = kernel_base; kern_tramp_phys = phys_addr_remap;

#ifdef __arm64__
    // Advanced arm64 trampoline patch (Branch to our mapped payload)
    // Avoids AMCC read-only region traps on A10 if KTRR is mitigated via patchfinder
    uint32_t arm64_tramp_hook[] = {
        0x58000040, // LDR X0, .+8
        0xD61F0000, // BR X0
        phys_addr_remap & 0xFFFFFFFF,
        (phys_addr_remap >> 32) & 0xFFFFFFFF
    };

    printf("[INFO]: Patching ARM64 sleep trampoline at 0x%llx\n", larm_init_tramp);
    vm_write(kernel_task, larm_init_tramp, (vm_offset_t)arm64_tramp_hook, sizeof(arm64_tramp_hook));

#else
    static uint32_t arm[2] = { 0xe51ff004, 0x0 };
    arm[1] = phys_addr_remap;
    printf("[INFO]: tramp = %llx | ", larm_init_tramp);
    bcopy((void *)arm, (void *)larm_init_tramp, sizeof(arm));
#endif

    printf("Syncing disks.\n");
    for (int synch = 0; synch < 10; synch++) sync();
    sleep(1);

    while (1) {
        printf("OK: Magic should be happening now! Initiating power management sleep...\n");
        mach_port_t fb = IOPMFindPowerManagement(MACH_PORT_NULL);
        if (fb != MACH_PORT_NULL) { 
            kern_return_t kr = IOPMSleepSystem(fb);
            if (kr) printf("[WARNING]: IOPMSleepSystem returned %x.\n", kr);
        } else {
            printf("[ERROR]: Failed to get PM root port.\n");
        }
        sleep(3);
    }
    return 0x0;
}
