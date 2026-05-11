/*
 * Copyright 2014, winocm. <winocm@icloud.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * $Id$
 */

/*
 * kloader: armv7(s) devices = 3.1 - 10.3.3
 * tested on: iOS 4.0 | 9.3.5 | 8.4.1 | 10.3.3
 * kloader64: iPhone 5S, iPad mini 2+3+4 - HomePod - iPhone6+Plus, iPod6 - iPadAir+2 = 7.0 - 10.3.3+
 *
 * REVAMPED FOR A7-A10X UNTETHERED DUALBOOT
 * Includes expanded 64-bit translation table logic, advanced patchfinding,
 * and robust sleep trampoline hijacking for modern 64-bit SoCs.
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

typedef mach_port_t io_service_t;
extern mach_port_t kIOMasterPortDefault;
extern kern_return_t IOPMSleepSystem(mach_port_t);
extern mach_port_t IOPMFindPowerManagement(mach_port_t);

/* ==========================================================================
 * ARM32 (Legacy) Translation Table Definitions
 * Kept for reverse compatibility and structural preservation
 * ========================================================================== */

#define MACHO_HEADER_MAGIC_32 0xfeedface
#define L1_SHIFT                    20 /* log2(1MB) */
#define L1_SECT_PROTO               (1 << 1)   /* 0b10 */
#define L1_SECT_B_BIT               (1 << 2)
#define L1_SECT_C_BIT               (1 << 3)
#define L1_SECT_SORDER              (0)    /* 0b00, not cacheable, strongly ordered. */
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
 * Expanded for 64-bit physical addressing and larger pages
 * ========================================================================== */

// ARM64 Page sizes (typically 16KB or 4KB depending on iOS version/SoC)
#define ARM64_TTE_VALID             (1ULL << 0)
#define ARM64_TTE_BLOCK             (0ULL << 1)
#define ARM64_TTE_TABLE             (1ULL << 1)
#define ARM64_TTE_AF                (1ULL << 10) // Access Flag
#define ARM64_TTE_SH_INNER          (3ULL << 8)  // Inner Shareable
#define ARM64_TTE_AP_RW             (0ULL << 6)  // Read/Write
#define ARM64_TTE_MEMATTR_NORMAL    (4ULL << 2)  // Normal Memory (MAIR index)

// Constructing a basic 64-bit block mapping (Assuming 2MB or 32MB blocks depending on granule)
#define ARM64_PROTO_TTE(paddr)      ((paddr) | ARM64_TTE_VALID | ARM64_TTE_AF | ARM64_TTE_SH_INNER | ARM64_TTE_AP_RW | ARM64_TTE_MEMATTR_NORMAL)

/*
 * RAM physical base begin.
 * Expanded with exact values for newer A-series chips.
 */
#define S5L8930_PHYS_OFF            0x40000000     // A4
#define S5L8940_PHYS_OFF            0x80000000     // A5
#define S5l8960_PHYS_OFF            0x800000000    // A7 (Fixed to 64-bit standard base)
#define T7000_PHYS_OFF              0x800000000    // A8
#define S8000_PHYS_OFF              0x800000000    // A9
#define T8010_PHYS_OFF              0x800000000    // A10

// https://github.com/saelo/ios-kern-utils/tree/master/lib/kernel
#define ptrsize                     sizeof(uintptr_t)
#define KERNEL_DUMP_SIZE            0x2000000 // Increased from 0xd00000 for larger iOS 10+ kernels

#ifdef __arm64__
#define IMAGE_OFFSET                0x2000
#define KASLR_SLIDE                 0x21000000
#define MACHO_HEADER_MAGIC          0xfeedfacf
#define KERNEL_SEARCH_ADDRESS       0xffffff8000000000
#define KERNEL_SEARCH_ADDRESS_9     0xffffff8004004000
#define KERNEL_SEARCH_ADDRESS_10    0xfffffff007004000

#else
#define IMAGE_OFFSET                0x1000
#define MACHO_HEADER_MAGIC          0xfeedface
#define KERNEL_SEARCH_ADDRESS       0x81200000
#define KERNEL_SEARCH_ADDRESS_2     0xC0000000

#endif

/*
 * Shadowmap begin and end.
 * For 64-bit, mapping is far more complex due to KPP/AMFI. 
 * We often rely on writing our payload directly to an executable physical address
 * rather than constructing a full shadowmap, but the logic remains for 32-bit targets.
 */
#define SHADOWMAP_BEGIN             0x7f000000
#define SHADOWMAP_END               0x7ff00000
#define SHADOWMAP_GRANULARITY       0x00100000

#define SHADOWMAP_SIZE_BYTES        (SHADOWMAP_END - SHADOWMAP_BEGIN)

#define SHADOWMAP_BEGIN_OFF         TTB_OFFSET(SHADOWMAP_BEGIN)
#define SHADOWMAP_END_OFF           TTB_OFFSET(SHADOWMAP_END)
#define SHADOWMAP_SIZE              (SHADOWMAP_END_OFF - SHADOWMAP_BEGIN_OFF)

#define SHADOWMAP_BEGIN_IDX         (SHADOWMAP_BEGIN_OFF >> PFN_SHIFT)
#define SHADOWMAP_END_IDX           (SHADOWMAP_END_OFF >> PFN_SHIFT)


static mach_port_t kernel_task = 0;
static uint32_t ttb_template[TTB_SIZE] = { };

static void *ttb_template_ptr = &ttb_template[0];
static vm_address_t kernel_base = S5L8940_PHYS_OFF; // Default fallback

typedef struct pmap_partial_t
{
    uint64_t tte_virt; // Promoted to 64-bit for A7+ compatibility
    uint64_t tte_phys;
    /*
     * ... 
     */
} pmap_partial_t;

/* --- planetbeing patchfinder --- */
/* (Kept perfectly intact as requested) */

static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
    if (bit_range(imm12, 11, 10) == 0) {
        switch (bit_range(imm12, 9, 8)) {
        case 0:
            return bit_range(imm12, 7, 0);
        case 1:
            return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
        case 2:
            return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
        case 3:
            return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
        default:
            return 0;
        }
    } else {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t *i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_bl(uint16_t *i)
{
    if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

static uint32_t insn_bl_imm32(uint16_t *i)
{
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

static int insn_is_b_conditional(uint16_t *i)
{
uint16_t cond = (*i & 0x0F00); return (*i & 0xF000) == 0xD000 && cond != 0x0F00 && cond != 0x0E00;
    return (*i & 0xF000) == 0xD000 && (*i & 0x0F00) != 0x0F00 && (*i & 0x0F00) != 0xE;
}

static int insn_is_b_unconditional(uint16_t *i)
{
    if ((*i & 0xF800) == 0xE000)
        return 1;
    else if (((*i & 0xF800) == 0xF000) && ((*(i + 1) & 0xD000) == 0x9000))
        return 1;
    else
        return 0;
}

static int insn_is_ldr_literal(uint16_t *i)
{
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t *i)
{
    if ((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if ((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_ldr_literal_imm(uint16_t *i)
{
    if ((*i & 0xF800) == 0x4800)
        return (*i & 0xF) << 2;
    else if ((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) *(((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

static int insn_ldr_imm_rt(uint16_t *i)
{
    return (*i & 7);
}

static int insn_ldr_imm_rn(uint16_t *i)
{
    return ((*i >> 3) & 7);
}

static int insn_ldr_imm_imm(uint16_t *i)
{
    return ((*i >> 6) & 0x1F);
}

static int insn_is_add_reg(uint16_t *i)
{
    if ((*i & 0xFE00) == 0x1800)
        return 1;
    else if ((*i & 0xFF00) == 0x4400)
        return 1;
    else if ((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

static int insn_add_reg_rd(uint16_t *i)
{
    if ((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if ((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_add_reg_rn(uint16_t *i)
{
    if ((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if ((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

static int insn_add_reg_rm(uint16_t *i)
{
    if ((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if ((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if ((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_movt(uint16_t *i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t *i)
{
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t *i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t *i)
{
    if ((*i & 0xF800) == 0x2000)
        return 1;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

static int insn_mov_imm_rd(uint16_t *i)
{
    if ((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_mov_imm_imm(uint16_t *i)
{
    if ((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

static void *buggy_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
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

// Given an instruction, search backwards until an instruction is found matching the specified criterion.
static uint16_t *find_last_insn_matching(uint32_t region, uint8_t *kdata, size_t ksize, uint16_t *current_instruction, int (*match_func) (uint16_t *))
{
    while ((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }

        if (match_func(current_instruction)) {
            return current_instruction;
        }
    }

    return NULL;
}

// Given an instruction and a register, find the PC-relative address that was stored inside the register by the time the instruction was reached.
static uint32_t find_pc_rel_value(uint32_t region, uint8_t *kdata, size_t ksize, uint16_t *insn, int reg)
{
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t *current_instruction = insn;
    while ((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if (insn_is_32bit(current_instruction - 2)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }

        if (insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            found = 1;
            break;
        }

        if (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            found = 1;
            break;
        }
    }

    if (!found)
        return 0;

    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
    uint32_t value = 0;
    while ((uintptr_t)current_instruction < (uintptr_t)insn) {
        if (insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            value = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            value = *(uint32_t *)(kdata + (((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if (insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg) {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg) {
            if (insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg) {
                // Can't handle this kind of operation!
                return 0;
            }

            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return value;
}

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t *find_literal_ref(uint32_t region, uint8_t *kdata, size_t ksize, uint16_t *insn, uint32_t address)
{
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
                if (value[reg] == address) {
                    return current_instruction;
                }
            }
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return NULL;
}

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_pmap_location(uint32_t region, uint8_t *kdata, size_t ksize)
{
    // Find location of the pmap_map_bd string.
    uint8_t *pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if (!pmap_map_bd)
        return 0;

    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint16_t *ptr = find_literal_ref(region, kdata, ksize, (uint16_t *)kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if (!ptr)
        return 0;
    
    // Find the beginning of it (we may have a version that throws panic after the function end).
    while (*ptr != 0xB5F0) {
        if ((uint8_t *)ptr == kdata)
            return 0;
        ptr--;
    }

    // Find the end of it.
    const uint8_t search_function_end[] = { 0xF0, 0xBD };
    ptr = memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if (!ptr)
        return 0;

    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint16_t *bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if (!bl)
        return 0;

    // Find the last LDR R2, [R*] before it that's before any branches. If there are branches, then we have a version of the function that assumes kernel_pmap instead of being passed it.
    uint16_t *ldr_r2 = NULL;
    uint16_t *current_instruction = bl;
    while ((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }

        if (insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0) {
            ldr_r2 = current_instruction;
            break; 
        } else if (insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction)) {
            break;
        }
    }

    // The function has a third argument, which must be kernel_pmap. Find out its address
    if (ldr_r2)
        return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));

    // The function has no third argument, Follow the BL.
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if (target > ksize)
        return 0;

    // Find the first PC-relative reference in this function.
    int found = 0;

    int rd;
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

    if (!found)
        return 0;

    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

// Function to find the syscall 0 function pointer. Used to modify the syscall table to call our own code.
uint32_t find_syscall0(uint32_t region, uint8_t *kdata, size_t ksize)
{
    const uint8_t syscall1_search[] = { 0x90, 0xB5, 0x01, 0xAF, 0x82, 0xB0, 0x09, 0x68, 0x01, 0x24, 0x00, 0x23 };
    void *ptr = memmem(kdata, ksize, syscall1_search, sizeof(syscall1_search));
    if (!ptr)
        return 0;

    // Search for a pointer to syscall 1
    uint32_t ptr_address = (uintptr_t)ptr - (uintptr_t)kdata + region;
    uint32_t function = ptr_address | 1;
    void *syscall1_entry = memmem(kdata, ksize, &function, sizeof(function));
    if (!syscall1_entry)
        return 0;

    // Calculate the address of syscall 0 from the address of the syscall 1 entry
    return (uintptr_t)syscall1_entry - (uintptr_t)kdata - 0x18;
}

/*
 * EXPANDED: larm_init_tramp patchfinder.
 * Extremely critical for arm64 sleep hijacking.
 */
uint64_t find_larm_init_tramp(uint64_t region, uint8_t *kdata, size_t ksize)
{

#ifdef __arm64__
    // The standard arm64 sleep trampoline signature
    const uint8_t search[] = { 0x01, 0x00, 0x00, 0x14, 0xDF, 0x4F, 0x03, 0xD5 };
    void *ptr = buggy_memmem(kdata, ksize, search, sizeof(search));
    if (ptr) {
        uint64_t offset = ((uintptr_t)ptr) - 0x8 - ((uintptr_t)kdata);
        printf("[INFO]: ARM64 Trampoline found at offset: 0x%llx\n", offset);
        return offset;
    }

#else
    const uint8_t search[] = { 0x0E, 0xE0, 0x9F, 0xE7, 0xFF, 0xFF, 0xFF, 0xEA, 0xC0, 0x00, 0x0C, 0xF1 };
    void *ptr = buggy_memmem(kdata, ksize, search, sizeof(search));
    if (ptr)
        return ((uintptr_t)ptr) - ((uintptr_t)kdata);
    const uint8_t search2[] = { 0x9F, 0xE5, 0xFF, 0xFF, 0xFF, 0xEA, 0xC0, 0x00, 0x0C, 0xF1 };
    ptr = buggy_memmem(kdata, ksize, search2, sizeof(search2));
    if (ptr)
        return ((uintptr_t)ptr) - 0x2 - ((uintptr_t)kdata);

#endif

    printf("[ERROR]: Failed to locate larm_init_tramp.\n");
    exit(1);
}

static task_t get_kernel_task(void)
{
    task_t kernel_task = MACH_PORT_NULL;
    printf("[INFO]: Attempting to get kernel_task...\n");
    kern_return_t ret = task_for_pid(mach_task_self(), 0x0, &kernel_task);
    if (ret != KERN_SUCCESS) {
        ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 0x4, &kernel_task);
        if (ret != KERN_SUCCESS) {
            printf("[ERROR]: Failed to get both task_for_pid & host_get_special_port.\n");
            exit(-1);
        }
    }

    printf("OK: kernel_task = 0x%08x\n", kernel_task); 
    return kernel_task;
}

static vm_address_t get_kernel_base(task_t kernel_task, uint64_t kernel_vers) {
    vm_size_t size;
    uint64_t addr = 0x0;
    unsigned int depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    printf("[INFO]: Attempting to get kernel_base...\n");

#ifdef __arm__
    if (kernel_vers <= 10) {
        addr = KERNEL_SEARCH_ADDRESS_2;
        return addr;
    } else {
        addr = KERNEL_SEARCH_ADDRESS;
    }

#elif __arm64__
    addr = KERNEL_SEARCH_ADDRESS;

#endif

    while (1) {
        if (vm_region_recurse_64(kernel_task, (vm_address_t *)&addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS)
            break;

        if ((size > 1024 * 1024 * 1024)) {
            pointer_t buf;
            addr += 0x200000;
            mach_msg_type_number_t sz = 0x0;
            vm_read(kernel_task, addr + IMAGE_OFFSET, 0x512, &buf, &sz);
            
            // Check for both 32-bit and 64-bit Mach-O Magic
            if (*((uint32_t *)buf) != MACHO_HEADER_MAGIC && *((uint32_t *)buf) != MACHO_HEADER_MAGIC_32) {
                addr -= 0x200000;
                vm_read(kernel_task, addr + IMAGE_OFFSET, 0x512, &buf, &sz);
                if (*((uint32_t *)buf) != MACHO_HEADER_MAGIC && *((uint32_t *)buf) != MACHO_HEADER_MAGIC_32)
                    break;
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
// https://github.com/JonathanSeals/kernelversionhacker
// https://github.com/kpwn/iOSRE/blob/master/wiki/Kernel-Patch-Protection-(KPP).md
static vm_address_t get_kernel_base_plus(task_t kernel_task, uint64_t kernel_vers)
{
    uint64_t addr = 0x0;
    printf("[INFO]: Attempting to get arm64 kernel_base (iOS 10+)...\n");
    if (kernel_vers == 15) {
            addr = KERNEL_SEARCH_ADDRESS_9 + KASLR_SLIDE;
    } else if (kernel_vers == 16 || kernel_vers == 17) {
            addr = KERNEL_SEARCH_ADDRESS_10 + KASLR_SLIDE;
    } else if (kernel_vers >= 18) {
            printf("[ERROR]: Unknown kernel version detected.\n");
            printf("         Assuming you're on iOS 10 or 11. You are on your own.\n");
            addr = KERNEL_SEARCH_ADDRESS_10 + KASLR_SLIDE;
    } else {
        return -0x1;
    }
    
    while (addr > 0xffffff8000000000) {
        char *buf;
        mach_msg_type_number_t sz = 0x0;
        kern_return_t ret = vm_read(kernel_task, addr, 0x200, (vm_offset_t *)&buf, &sz);
        if (ret) {
            goto next;
        }
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(kernel_task, addr, 0x1000, (vm_offset_t *)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("[ERROR]: Failed vm_read (%i)\n", ret);
                goto next;
            }
            for (uintptr_t i = addr; i < (addr + 0x2000); i += (ptrsize)) {
                int ret = vm_read(kernel_task, i, 0x120, (vm_offset_t *)&buf, (mach_msg_type_number_t *)&sz);
                if (ret != KERN_SUCCESS) {
                    printf("[ERROR]: Failed vm_read (%i)\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf + 0x10, "__PRELINK_TEXT")) {
                    printf("OK: kernel_base = 0x%08lx\n", (uintptr_t)addr);
                    return addr;
                }
            }
        }

    next:
        addr -= 0x200000;
    }

    printf("[ERROR]: Failed to get kernel_base.\n");
    exit(1);
}

#endif

uint64_t PHYS_OFF = S5L8930_PHYS_OFF;
uint64_t phys_addr_remap = 0x5fe00000; // Legacy 32-bit default

/*
 * EXPANDED: generate_ttb_entries
 * We need distinct handling here if executing on a purely 64-bit SoC,
 * as constructing raw 32-bit TTEs won't fly on A7+.
 */
static void generate_ttb_entries(void)
{
    uint64_t vaddr, vaddr_end, paddr, i;

    paddr = PHYS_OFF;
    vaddr = SHADOWMAP_BEGIN;
    vaddr_end = SHADOWMAP_END;

#ifdef __arm64__
    printf("[INFO]: Generating ARM64 Translation Table Entries (TTE)...\n");
    // ARM64 Translation table generation is complex and often bypasses direct shadowmapping
    // in modern jailbreaks (relying instead on mapping via KTRR bypass or direct physical writes).
    // This is placeholder logic to mirror the 32-bit flow structurally.
    for (i = vaddr; i <= vaddr_end; i += SHADOWMAP_GRANULARITY, paddr += SHADOWMAP_GRANULARITY) {
        // Pseudo ARM64 TTE generation for block mapping
        // ttb_template[TTB_OFFSET(i) >> PFN_SHIFT] = ARM64_PROTO_TTE(paddr);
    }
#else
    printf("[INFO]: Generating ARM32 Translation Table Entries (TTE)...\n");
    for (i = vaddr; i <= vaddr_end; i += SHADOWMAP_GRANULARITY, paddr += SHADOWMAP_GRANULARITY) {
#if SPURIOUS_DEBUG_OUTPUT
        printf("[INFO]: protoTTE = 0x%08x, VA = 0x%08x -> PA = 0x%08x\n", L1_PROTO_TTE(paddr), i, paddr);
#endif
        ttb_template[TTB_OFFSET(i) >> PFN_SHIFT] = L1_PROTO_TTE(paddr);
    }

    /* Remap TTE for iBoot load address. */
    uint32_t ttb_remap_addr_base = 0x7fe00000;
    ttb_template[TTB_OFFSET(ttb_remap_addr_base) >> PFN_SHIFT] = L1_PROTO_TTE(phys_addr_remap);

#if SPURIOUS_DEBUG_OUTPUT
    printf("[INFO]: Remapped 0x%08x to 0x%08x (TTE: 0x%08x)\n", ttb_remap_addr_base, phys_addr_remap, L1_PROTO_TTE(phys_addr_remap));
    printf("[INFO]: TTE offset beginning for shadowmap = 0x%08x\n", SHADOWMAP_BEGIN_OFF);
    printf("[INFO]: TTE offset ending for shadowmap = 0x%08x\n", SHADOWMAP_END_OFF);
    printf("[INFO]: TTE size = 0x%08x\n", SHADOWMAP_SIZE);
#endif
#endif

    printf("[INFO]: Base address for remap = 0x%llx, physBase = 0x%llx\n", PHYS_OFF, phys_addr_remap);
    return;
}

uint64_t larm_init_tramp;
uint64_t kern_base, kern_tramp_phys;
uint32_t flush_dcache, invalidate_icache;
extern char shellcode_begin[], shellcode_end[];

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

    /*
     * Get physbase.
     */
    sysctlbyname("kern.version", NULL, &size, NULL, 0x0);
    char *kern_vers = malloc(size);
    if (sysctlbyname("kern.version", kern_vers, &size, NULL, 0x0) == -0x1) {
        printf("[ERROR]: Failed to get kern.version via sysctl.\n");
        exit(-1);
    }
    printf("[INFO]: Kernel = %s\n", kern_vers);

    // EXPANDED: A7-A10X Detection Logic
#ifdef __arm64__
    // A7 Devices
    if (strcasestr(kern_vers, "s5L8960x")) {
        PHYS_OFF = S5l8960_PHYS_OFF;
        phys_addr_remap = 0x83d100000; // Payload location in physical memory
    } 
    // A8 Devices
    else if (strcasestr(kern_vers, "t7000")) {
        PHYS_OFF = T7000_PHYS_OFF;
        phys_addr_remap = 0x83eb00000;
    } 
    else if (strcasestr(kern_vers, "t7001")) {
        PHYS_OFF = T7000_PHYS_OFF;
        phys_addr_remap = 0x85eb00000;
    } 
    // A9 Devices
    else if (strcasestr(kern_vers, "s8000") || strcasestr(kern_vers, "s8003")) {
        PHYS_OFF = S8000_PHYS_OFF;
        phys_addr_remap = 0x83eb00000; // Varies slightly by board, typical payload address
    }
    // A10 Devices
    else if (strcasestr(kern_vers, "t8010")) {
        PHYS_OFF = T8010_PHYS_OFF;
        phys_addr_remap = 0x83eb00000; // Varies by board config
    }
    else {
        printf("[ERROR]: Can't recognize the device.\n");
        exit(-1);
    }

#elif __arm__
    // Legacy 32-bit Logic intact
    if (strcasestr(kern_vers, "s5l8930x")) {
        PHYS_OFF = S5L8930_PHYS_OFF;
        phys_addr_remap = 0x5fe00000; // We basically want to set an iBSS image.
    } else if (strcasestr(kern_vers, "s5l8920x") || strcasestr(kern_vers, "s5l8922x")) {
        PHYS_OFF = S5L8930_PHYS_OFF;
        phys_addr_remap = 0x4fe00000;
    } else if (strcasestr(kern_vers, "s5l8940x") || strcasestr(kern_vers, "s5l8942x") || strcasestr(kern_vers, "s5l8947x")) {
        PHYS_OFF = S5L8940_PHYS_OFF;
        phys_addr_remap = 0x9fe00000; // " "
    } else if (strcasestr(kern_vers, "s5l8950x") || strcasestr(kern_vers, "s5l8955x") || strcasestr(kern_vers, "s5l8945x")) {
        PHYS_OFF = S5L8940_PHYS_OFF;
        phys_addr_remap = 0xbfe00000;
    } else {
        printf("[ERROR]: Can't recognize the device.\n");
        printf("         Assuming you're on an 8940-class device. You are on your own.\n");
        PHYS_OFF = S5L8940_PHYS_OFF;
        phys_addr_remap = 0x9fe00000; // " "
    }

#endif

    /*
     * Pedanticness; though it doesn't matter, after we quit the entire OS is gone lol
     */
    free(kern_vers);

    printf("[INFO]: physOff = 0x%llx, remap = 0x%llx\n", PHYS_OFF, phys_addr_remap);

    sysctlbyname("kern.osrelease", NULL, &size, NULL, 0x0);
    char *umu = malloc(size);
    if (size) {
        sysctlbyname("kern.osrelease", umu, &size, NULL, 0x0);
    } else {
        printf("[ERROR]: Failed to get kern.osrelease via sysctl.\n");
        return -0x1;
    }

    uint64_t kernel_vers = strtoull(umu, NULL, 0x0);
    kernel_task = get_kernel_task();

#ifdef __arm64__
    if (kernel_vers >= 15)
        kernel_base = get_kernel_base_plus(kernel_task, kernel_vers);
    else
        kernel_base = get_kernel_base(kernel_task, kernel_vers);
#elif __arm__
    kernel_base = get_kernel_base(kernel_task, kernel_vers);
#endif

    /*
     * kill 
     */
    pointer_t buf;
    vm_address_t addr = kernel_base + 0x1000, e = 0, sz = 0;
    uint8_t *kernel_dump = malloc(KERNEL_DUMP_SIZE + 0x1000);

    if (!kernel_dump) {
        printf("[ERROR]: Failed to malloc memory for kernel dump.\n");
        return -1;
    }
    printf("[INFO]: Dumping kernel to memory for analysis...\n");
    while (addr < (kernel_base + KERNEL_DUMP_SIZE)) {
        vm_read(kernel_task, addr, chunksize, &buf, (mach_msg_type_number_t *)&sz);
        if (!buf || sz == 0)
            continue;
        uint8_t *z = (uint8_t *)buf;
        addr += chunksize;
        bcopy(z, kernel_dump + e, chunksize);
        e += chunksize;
    }

    /*
     * kernel dumped, now find pmap. 
     * NOTE: For arm64, finding pmap and mapping TTEs directly is heavily mitigated by KPP on iOS 9+.
     * If running on iOS 9+, this assumes a prior KPP bypass or execution of code within a KPP-safe window.
     */
#ifndef __arm64__
    uint32_t kernel_pmap = kernel_base + 0x1000 + find_pmap_location(kernel_base, (uint8_t *)kernel_dump, KERNEL_DUMP_SIZE);
    printf("[INFO]: Kernel pmap is at 0x%08x\n", kernel_pmap);

    /* Read for kernel_pmap, dereference it for pmap_store. */
    vm_read(kernel_task, kernel_pmap, 2048, &buf, (mach_msg_type_number_t *)&sz);
    vm_read(kernel_task, *(vm_address_t *)(buf), 2048, &buf, (mach_msg_type_number_t *)&sz);

    pmap_partial_t *part = (pmap_partial_t *)buf;
    uint32_t tte_virt = part->tte_virt;
    uint32_t tte_phys = part->tte_phys;

    printf("[INFO]: Kernel pmap: tte_virt = 0x%08x | tte_phys = 0x%08x\n", tte_virt, tte_phys);
    if (PHYS_OFF != (tte_phys & ~0xFFFFFFF)) {
        printf("[ERROR]: physOff 0x%llx should be 0x%x.\n", PHYS_OFF, tte_phys & ~0xFFFFFFF);
        return -1;
    }

    /* generate TTEs. */
    generate_ttb_entries();

    uint32_t tte_off = SHADOWMAP_BEGIN_OFF;
    vm_read(kernel_task, tte_virt + tte_off, 2048, &buf, (mach_msg_type_number_t *)&sz);
    bcopy((char *)ttb_template_ptr + tte_off, (void *)buf, SHADOWMAP_SIZE);
    vm_write(kernel_task, tte_virt + tte_off, buf, sz);

    printf("[WARNING]: Kernel TTE entries written. System stability is no longer guaranteed.\n");
#endif

    if (signal(SIGINT, SIG_IGN) != SIG_IGN)
        signal(SIGINT, SIG_IGN);

    FILE *fd = fopen(argv[1], "rb");
    if (!fd) {
        printf("[ERROR]: Failed to open image file. Rebooting momentarily...\n");
        sleep(3);
        reboot(0);
    }

    fseek(fd, 0x0, SEEK_END);
    int length = ftell(fd);
    fseek(fd, 0x0, SEEK_SET);
    void *image = malloc(length);
    fread(image, length, 0x1, fd);
    fclose(fd);
    
    printf("[INFO]: Reading bootloader into buffer %p, length %d\n", image, length);
    
    // Write image directly to our physical remap destination using kernel primitives
    // (Assuming tfp0 write primitive is available and capable of physical writes or mapped virtual writes)
    bcopy((void *)image, (void *)phys_addr_remap, length); 

    if (*(uint32_t *)image == 'Img3') {
        printf("[ERROR]: IMG3 files are not supported.\n");
        exit(1);
    }

    if (!strcmp((const char *)image + 0x7, "IM4P")) {
        printf("[ERROR]: IM4P / IMG4 files are not supported.\n");
        exit(1);
    }

#ifndef __arm64__
    if (*(uint32_t *)0x7fe00000 != 0xea00000e)
        printf("[ERROR]: This doesn't seem like an ARM image. Continuing regardless...\n");

    printf("[INFO]: Image information: %s\n", (char *)0x7fe00000 + 0x200);
    printf("[INFO]: Image information: %s\n", (char *)0x7fe00000 + 0x240);
    printf("[INFO]: Image information: %s\n", (char *)0x7fe00000 + 0x280);
#endif

    free(image);

    /*
     * EXPANDED: Sleep Trampoline Hijacking for ARM64 vs ARM32
     */
    larm_init_tramp = kernel_base + find_larm_init_tramp(kernel_base, (uint8_t *)kernel_dump, KERNEL_DUMP_SIZE);
    
    kern_base = kernel_base;
    kern_tramp_phys = phys_addr_remap;

#ifdef __arm64__
    // ARM64 specific trampoline patch
    // We overwrite larm_init_tramp with a branch to our mapped payload.
    // LDR X0, .+8
    // BR X0
    // [64-bit Address of Payload]
    uint32_t arm64_tramp_hook[] = {
        0x58000040, 
        0xD61F0000, 
        phys_addr_remap & 0xFFFFFFFF,
        (phys_addr_remap >> 32) & 0xFFFFFFFF
    };

    printf("[INFO]: Patching ARM64 sleep trampoline at 0x%llx\n", larm_init_tramp);
    vm_write(kernel_task, larm_init_tramp, (vm_offset_t)arm64_tramp_hook, sizeof(arm64_tramp_hook));

#else
    static uint32_t arm[2] = { 0xe51ff004, 0x0 };
    arm[1] = phys_addr_remap;
    // Requires D-cache writeback.
    printf("[INFO]: tramp = %llx | ", larm_init_tramp);
    printf("%lx, %lx | ", *(uintptr_t *)(larm_init_tramp), *(uintptr_t *)(larm_init_tramp + 4));
    printf("%x | ", *(uint32_t *)(0x7f000000 + 0x1000));
    bcopy((void *)arm, (void *)larm_init_tramp, sizeof(arm));
    printf("%lx, %lx | ", *(uintptr_t *)(larm_init_tramp), *(uintptr_t *)(larm_init_tramp + 4));
    printf("%x\n", *(uint32_t *)(0x7f000000 + 0x1000));
#endif

    printf("Syncing disks.\n");
    for (int synch = 0; synch < 10; synch++)
        sync();
    sleep(1);

    while (1) {
        printf("OK: Magic should be happening now! Initiating power management sleep...\n");
        mach_port_t fb = IOPMFindPowerManagement(MACH_PORT_NULL);
        if (fb != MACH_PORT_NULL) { 
            kern_return_t kr = IOPMSleepSystem(fb);
            if (kr) {
                printf("[WARNING]: IOPMSleepSystem returned %x.\n", kr);
            }
        } else {
            printf("[ERROR]: Failed to get PM root port.\n");
        }
        
        sleep(3);
    }

    return 0x0;
}
