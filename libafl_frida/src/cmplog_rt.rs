//! Functionality for [`frida`](https://frida.re)-based binary-only `CmpLog`.
//! With it, a fuzzer can collect feedback about each compare that happened in the target
//! This allows the fuzzer to potentially solve the compares, if a compare value is directly
//! related to the input.
//! Read the [`RedQueen`](https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/) paper for the general concepts.
use std::ffi::c_void;

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
#[cfg(target_arch = "aarch64")]
use frida_gum_sys::Insn;
use libafl::{
    inputs::{HasTargetBytes, Input},
    Error,
};
use libafl_targets::{self, CMPLOG_MAP_W};
use rangemap::RangeMap;

use crate::helper::FridaRuntime;
extern "C" {
    /// Tracks cmplog instructions
    pub fn __libafl_targets_cmplog_instructions(k: u64, shape: u8, arg1: u64, arg2: u64);
}

use std::rc::Rc;

use frida_gum::ModuleMap;
#[cfg(target_arch = "aarch64")]
use frida_gum::{
    instruction_writer::{Aarch64Register, IndexMode, InstructionWriter},
    stalker::StalkerOutput,
};

#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
use crate::utils::{disas_count, writer_register};

#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
/// Speciial `CmpLog` Cases for `aarch64`
#[derive(Debug)]
pub enum SpecialCmpLogCase {
    /// Test bit and branch if zero
    Tbz,
    /// Test bit and branch if not zero
    Tbnz,
}

#[cfg(target_arch = "aarch64")]
use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode, Operand, ShiftStyle};

/// The [`frida_gum_sys::GUM_RED_ZONE_SIZE`] casted to [`i32`]
///
/// # Panic
/// In debug mode, will panic on wraparound (which should never happen in practice)
#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
#[allow(clippy::cast_possible_wrap)]
fn gum_red_zone_size_i32() -> i32 {
    debug_assert!(
        i32::try_from(frida_gum_sys::GUM_RED_ZONE_SIZE).is_ok(),
        "GUM_RED_ZONE_SIZE is bigger than i32::max"
    );
    frida_gum_sys::GUM_RED_ZONE_SIZE as i32
}

/// The type of an operand loggged during `CmpLog`
#[derive(Debug, Clone, Copy)]
#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
pub enum CmplogOperandType {
    /// A Register
    Regid(Aarch64Register),
    /// An immediate value
    Imm(u64),
    /// A constant immediate value
    Cimm(u64),
    // We don't need a memory type because you cannot directly compare with memory
}

/// `Frida`-based binary-only innstrumentation that logs compares to the fuzzer
/// `LibAFL` can use this knowledge for powerful mutations.
#[derive(Debug)]
pub struct CmpLogRuntime {
    ops_save_register_and_blr_to_populate: Option<Box<[u8]>>,
    ops_handle_tbz_masking: Option<Box<[u8]>>,
    ops_handle_tbnz_masking: Option<Box<[u8]>>,
}

impl FridaRuntime for CmpLogRuntime {
    /// Initialize this `CmpLog` runtime.
    /// This will generate the instrumentation blobs for the current arch.
    fn init(
        &mut self,
        _gum: &frida_gum::Gum,
        _ranges: &RangeMap<usize, (u16, String)>,
        _module_map: &Rc<ModuleMap>,
    ) {
        self.generate_instrumentation_blobs();
    }

    fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}

impl CmpLogRuntime {
    /// Create a new [`CmpLogRuntime`]
    #[must_use]
    pub fn new() -> CmpLogRuntime {
        Self {
            ops_save_register_and_blr_to_populate: None,
            ops_handle_tbz_masking: None,
            ops_handle_tbnz_masking: None,
        }
    }

    /// Call the external function that populates the `cmplog_map` with the relevant values
    #[allow(clippy::unused_self)]
    extern "C" fn populate_lists(&mut self, op1: u64, op2: u64, retaddr: u64) {
        // log::trace!(
        //     "entered populate_lists with: {:#02x}, {:#02x}, {:#02x}",
        //     op1, op2, retaddr
        // );
        let mut k = (retaddr >> 4) ^ (retaddr << 8);

        k &= (CMPLOG_MAP_W as u64) - 1;

        unsafe {
            __libafl_targets_cmplog_instructions(k, 8, op1, op2);
        }
    }

    /// Generate the instrumentation blobs for the current arch.
    #[allow(clippy::similar_names)]
    fn generate_instrumentation_blobs(&mut self) {
        macro_rules! blr_to_populate {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x2, x3, [sp, #-0x10]!
                ; stp x4, x5, [sp, #-0x10]!
                ; stp x6, x7, [sp, #-0x10]!
                ; stp x8, x9, [sp, #-0x10]!
                ; stp x10, x11, [sp, #-0x10]!
                ; stp x12, x13, [sp, #-0x10]!
                ; stp x14, x15, [sp, #-0x10]!
                ; stp x16, x17, [sp, #-0x10]!
                ; stp x18, x19, [sp, #-0x10]!
                ; stp x20, x21, [sp, #-0x10]!
                ; stp x22, x23, [sp, #-0x10]!
                ; stp x24, x25, [sp, #-0x10]!
                ; stp x26, x27, [sp, #-0x10]!
                ; stp x28, x29, [sp, #-0x10]!
                ; stp x30, xzr, [sp, #-0x10]!
                ; .dword 0xd53b4218u32 as i32 // mrs x24, nzcv
                // jump to rust based population of the lists
                ; mov x2, x0
                ; adr x3, >done
                ; ldr x4, >populate_lists
                ; ldr x0, >self_addr
                ; blr x4
                // restore the reg state before returning to the caller
                ; .dword 0xd51b4218u32 as i32 // msr nzcv, x24
                ; ldp x30, xzr, [sp], #0x10
                ; ldp x28, x29, [sp], #0x10
                ; ldp x26, x27, [sp], #0x10
                ; ldp x24, x25, [sp], #0x10
                ; ldp x22, x23, [sp], #0x10
                ; ldp x20, x21, [sp], #0x10
                ; ldp x18, x19, [sp], #0x10
                ; ldp x16, x17, [sp], #0x10
                ; ldp x14, x15, [sp], #0x10
                ; ldp x12, x13, [sp], #0x10
                ; ldp x10, x11, [sp], #0x10
                ; ldp x8, x9, [sp], #0x10
                ; ldp x6, x7, [sp], #0x10
                ; ldp x4, x5, [sp], #0x10
                ; ldp x2, x3, [sp], #0x10
                ; b >done
                ; self_addr:
                ; .qword self as *mut _  as *mut c_void as i64
                ; populate_lists:
                ; .qword  CmpLogRuntime::populate_lists as *mut c_void as i64
                ; done:
            );};
        }

        // ldp/stp is more efficient than str/ldr so we use them instead.
        macro_rules! tbz_masking {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x5, xzr, [sp, #-0x10]!
                ; mov x5, #1
                ; lsl x5, x5, x1
                ; eor x5, x5, #255
                ; orr x1, x0, x5
                ; ldp x5, xzr, [sp], #0x10
            );};
        }

        macro_rules! tbnz_masking {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x5, xzr, [sp, #-0x10]!
                ; mov x5, #1
                ; lsl x5, x5, x1
                ; orr x1, x0, x5
                ; ldp x5, xzr, [sp], #0x10
            );};

        }

        let mut ops_handle_tbz_masking =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        tbz_masking!(ops_handle_tbz_masking);

        let mut ops_handle_tbnz_masking =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        tbnz_masking!(ops_handle_tbnz_masking);

        let mut ops_save_register_and_blr_to_populate =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        blr_to_populate!(ops_save_register_and_blr_to_populate);

        self.ops_handle_tbz_masking = Some(
            ops_handle_tbz_masking
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );

        self.ops_handle_tbnz_masking = Some(
            ops_handle_tbnz_masking
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );

        self.ops_save_register_and_blr_to_populate = Some(
            ops_save_register_and_blr_to_populate
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );
    }

    /// Get the blob which saves the context, jumps to the populate function and restores the context
    #[inline]
    #[must_use]
    pub fn ops_save_register_and_blr_to_populate(&self) -> &[u8] {
        self.ops_save_register_and_blr_to_populate.as_ref().unwrap()
    }

    /// Get the blob which handles the tbz opcode masking
    #[inline]
    #[must_use]
    pub fn ops_handle_tbz_masking(&self) -> &[u8] {
        self.ops_handle_tbz_masking.as_ref().unwrap()
    }

    /// Get the blob which handles the tbnz opcode masking
    #[inline]
    #[must_use]
    pub fn ops_handle_tbnz_masking(&self) -> &[u8] {
        self.ops_handle_tbnz_masking.as_ref().unwrap()
    }

    /// Emit the instrumentation code which is responsible for operands value extraction and cmplog map population
    #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
    #[allow(clippy::too_many_lines)]
    #[inline]
    pub fn emit_comparison_handling(
        &self,
        _address: u64,
        output: &StalkerOutput,
        op1: &CmplogOperandType, //first operand of the comparsion
        op2: &CmplogOperandType, //second operand of the comparsion
        _shift: Option<(ShiftStyle, u8)>,
        special_case: Option<SpecialCmpLogCase>,
    ) {
        let writer = output.writer();

        // Preserve x0, x1:
        writer.put_stp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            i64::from(-(16 + gum_red_zone_size_i32())),
            IndexMode::PreAdjust,
        );

        // make sure operand1 value is saved into x0
        match op1 {
            CmplogOperandType::Imm(value) | CmplogOperandType::Cimm(value) => {
                writer.put_ldr_reg_u64(Aarch64Register::X0, *value);
            }
            CmplogOperandType::Regid(reg) => match *reg {
                Aarch64Register::X0 | Aarch64Register::W0 => {}
                Aarch64Register::X1 | Aarch64Register::W1 => {
                    writer.put_mov_reg_reg(Aarch64Register::X0, Aarch64Register::X1);
                }
                _ => {
                    if !writer.put_mov_reg_reg(Aarch64Register::X0, *reg) {
                        writer.put_mov_reg_reg(Aarch64Register::W0, *reg);
                    }
                }
            },
        }

        // make sure operand2 value is saved into x1
        match op2 {
            CmplogOperandType::Imm(value) | CmplogOperandType::Cimm(value) => {
                writer.put_ldr_reg_u64(Aarch64Register::X1, *value);
                if let Some(inst) = special_case {
                    match inst {
                        SpecialCmpLogCase::Tbz => {
                            writer.put_bytes(self.ops_handle_tbz_masking());
                        }
                        SpecialCmpLogCase::Tbnz => {
                            writer.put_bytes(self.ops_handle_tbnz_masking());
                        }
                    }
                }
            }
            CmplogOperandType::Regid(reg) => match *reg {
                Aarch64Register::X1 | Aarch64Register::W1 => {}
                Aarch64Register::X0 | Aarch64Register::W0 => {
                    writer.put_ldr_reg_reg_offset(Aarch64Register::X1, Aarch64Register::Sp, 0u64);
                }
                _ => {
                    if !writer.put_mov_reg_reg(Aarch64Register::X1, *reg) {
                        writer.put_mov_reg_reg(Aarch64Register::W1, *reg);
                    }
                }
            },
        }

        //call cmplog runtime to populate the values map
        writer.put_bytes(self.ops_save_register_and_blr_to_populate());

        // Restore x0, x1
        assert!(writer.put_ldp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            16 + i64::from(frida_gum_sys::GUM_RED_ZONE_SIZE),
            IndexMode::PostAdjust,
        ));
    }

    #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
    #[allow(clippy::similar_names)]
    #[inline]
    /// Check if the current instruction is cmplog relevant one(any opcode which sets the flags)
    #[must_use]
    pub fn cmplog_is_interesting_instruction(
        decoder: InstDecoder,
        _address: u64,
        instr: &Insn,
    ) -> Option<(
        CmplogOperandType,
        CmplogOperandType,
        Option<(ShiftStyle, u8)>, //possible shifts: everything except MSL
        Option<SpecialCmpLogCase>,
    )> {
        let mut instr = disas_count(&decoder, instr.bytes(), 1)[0];
        let operands_len = instr
            .operands
            .iter()
            .position(|item| *item == Operand::Nothing)
            .unwrap_or_else(|| 4);
        // "cmp" | "ands" | "subs" | "adds" | "negs" | "ngcs" | "sbcs" | "bics" | "cbz"
        //    | "cbnz" | "tbz" | "tbnz" | "adcs" - yaxpeax aliases insns (i.e., cmp -> subs)
        // We only care for compare instructions - aka instructions which set the flags
        match instr.opcode {
            Opcode::SUBS
            | Opcode::ANDS
            | Opcode::ADDS
            | Opcode::SBCS
            | Opcode::BICS
            | Opcode::CBZ
            | Opcode::CBNZ
            | Opcode::TBZ
            | Opcode::TBNZ
            | Opcode::ADC => (),
            _ => return None,
        }

        // cbz - 1 operand, everything else - 3 operands
        let special_case = [
            Opcode::CBZ,
            Opcode::CBNZ,
            Opcode::TBZ,
            Opcode::TBNZ,
            Opcode::SUBS,
            Opcode::ADDS,
            Opcode::ANDS,
            Opcode::SBCS,
            Opcode::BICS,
            Opcode::ADCS,
        ]
        .contains(&instr.opcode);
        //this check is to ensure that there are the right number of operands
        if operands_len != 2 && !special_case {
            return None;
        }

        // handle special opcodes case which have 3 operands, but the 1st(dest) is not important to us
        ////subs", "adds", "ands", "sbcs", "bics", "adcs"
        if [
            Opcode::SUBS,
            Opcode::ADDS,
            Opcode::ANDS,
            Opcode::SBCS,
            Opcode::BICS,
            Opcode::ADCS,
        ]
        .contains(&instr.opcode)
        {
            //remove the dest operand from the list
            instr.operands.rotate_left(1);
            instr.operands[3] = Operand::Nothing;
        }

        // cbz marked as special since there is only 1 operand
        #[allow(clippy::cast_sign_loss)]
        let special_case = matches!(instr.opcode, Opcode::CBZ | Opcode::CBNZ);

        #[allow(clippy::cast_sign_loss, clippy::similar_names)]
        let operand1 = match instr.operands[0] {
            //the only possibilities are registers for the first operand
            //precompute the aarch64 frida register because it is ambiguous if register=31 means xzr or sp in yaxpeax
            Operand::Register(sizecode, reg) => Some(CmplogOperandType::Regid(writer_register(
                reg, sizecode, true,
            ))),
            Operand::RegisterOrSP(sizecode, reg) => Some(CmplogOperandType::Regid(
                writer_register(reg, sizecode, false),
            )),
            _ => panic!("First argument is not a register"), //this should never be possible in arm64
        };

        #[allow(clippy::cast_sign_loss)]
        let operand2 = if special_case {
            Some((CmplogOperandType::Imm(0), None))
        } else {
            match instr.operands[1] {
                Operand::Register(sizecode, reg) => Some((
                    CmplogOperandType::Regid(writer_register(reg, sizecode, true)),
                    None,
                )),
                Operand::ImmShift(imm, shift) => {
                    Some((CmplogOperandType::Imm((imm as u64) << shift), None))
                } //precalculate the shift
                Operand::RegShift(shiftstyle, amount, regsize, reg) => {
                    let reg = CmplogOperandType::Regid(writer_register(reg, regsize, true));
                    let shift = (shiftstyle, amount);
                    Some((reg, Some(shift)))
                }
                Operand::Immediate(imm) => Some((CmplogOperandType::Imm(imm as u64), None)),
                _ => panic!("Second argument could not be decoded"),
            }
        };

        // tbz will need to have special handling at emit time(masking operand1 value with operand2)
        let special_case = match instr.opcode {
            Opcode::TBZ => Some(SpecialCmpLogCase::Tbz),
            Opcode::TBNZ => Some(SpecialCmpLogCase::Tbnz),
            _ => None,
        };

        if let Some(op1) = operand1 {
            operand2.map(|op2| (op1, op2.0, op2.1, special_case))
        } else {
            None
        }
    }
}

impl Default for CmpLogRuntime {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
