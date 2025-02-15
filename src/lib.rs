use binaryninja::logger::Logger;

use binaryninja::symbol::SymbolBuilder;
use binaryninja::types::StructureBuilder;
use binaryninja::{
    binary_view::{BinaryView, BinaryViewExt},
    command::{register_command, Command},
    symbol::SymbolType,
    types::{MemberAccess, MemberScope, Type},
};

use binaryninja::platform::Platform;
use log::{debug, LevelFilter};

use lief::pe::ExceptionInfo;

fn add_function(bv: &BinaryView, pe: &lief::pe::Binary, func_addr: u64) {
    // This function is not optimal and would need some kind 'IntervalMap' container,
    // but for the sake of simplicity, I keep it like this
    let imagebase = pe.optional_header().imagebase();
    if let Some(func) = bv.function_at(&bv.default_platform().unwrap(), func_addr) {
        bv.undefine_auto_symbol(&func.symbol());
        bv.undefine_user_symbol(&func.symbol());
    }

    let windows_arm64 = Platform::by_name("windows-aarch64").unwrap().to_owned();
    let windows_x64 = Platform::by_name("windows-x86_64").unwrap().to_owned();

    if let Some(lief::pe::CHPEMetadata::ARM64(arm64)) =
        pe.load_configuration().unwrap().chpe_metadata()
    {
        let func_rva = (func_addr - imagebase) as u32;
        for entry in arm64.code_ranges() {
            if entry.start() <= func_rva && func_rva < entry.end() {
                match entry.range_type() {
                    lief::pe::chpe_metadata_arm64::RangeType::ARM64 => {
                        bv.add_auto_function(&windows_arm64, func_addr);
                    }

                    lief::pe::chpe_metadata_arm64::RangeType::ARM64EC => {
                        bv.add_auto_function(&windows_arm64, func_addr);
                    }

                    lief::pe::chpe_metadata_arm64::RangeType::AMD64 => {
                        bv.add_auto_function(&windows_x64, func_addr);
                    }

                    _ => todo!(),
                }
            }
        }
    }
}

fn add_chpe_arm64_types(bv: &BinaryView, loadconfig: &lief::pe::LoadConfiguration) {
    let mut chpe_arm64_builder = StructureBuilder::new();
    let ulong_ty = Type::int(4, /*is_signed=*/ false);
    chpe_arm64_builder
        .append(
            &ulong_ty,
            "Version",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "CodeMap",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "CodeRangesToEntryPoints",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "RedirectionMetadata",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "__os_arm64x_dispatch_call_no_redirect",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "__os_arm64x_dispatch_ret",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "__os_arm64x_dispatch_call",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "__os_arm64x_dispatch_icall",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "__os_arm64x_dispatch_icall_cfg",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "AlternateEntryPoint",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "AuxiliaryIAT",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "CodeRangesToEntryPointsCount",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "RedirectionMetadataCount",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "GetX64InformationFunctionPointer",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "SetX64InformationFunctionPointer",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "ExtraRFETable",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "ExtraRFETableSize",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "__os_arm64x_dispatch_fptr",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
        .append(
            &ulong_ty,
            "AuxiliaryIATCopy",
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        );

    let chpe_arm64_ty = Type::structure(&chpe_arm64_builder.finalize());

    let chpe_addr = loadconfig.chpe_metadata_pointer().unwrap();
    bv.define_user_type("IMAGE_ARM64EC_METADATA", &chpe_arm64_ty);

    // Note(romain): It appears that we can't use `&chpe_arm64_ty` because binaryninja
    // performs a kind of "copy" during "define_user_type". This means that "define_user_data_var"
    // does not recognize &chpe_arm64_ty properly and we must "reload" the type that is registered
    // internally.
    bv.define_user_data_var(
        chpe_addr,
        &bv.type_by_name("IMAGE_ARM64EC_METADATA").unwrap(),
    );
    let chpe_arm64_metadata_sym =
        SymbolBuilder::new(SymbolType::Data, "chpe_arm64_metadata", chpe_addr).create();

    bv.define_user_symbol(&chpe_arm64_metadata_sym);
}

fn enhance_with_lief(bv: &BinaryView) {
    let filename = bv.file().filename();
    // Get a lief::pe::Binary instance from the BinaryNinja's BinaryView instance
    let pe = lief::pe::Binary::parse_with_config(
        filename.as_str(),
        // We need to enable `with_all_options` to access exceptions info
        lief::pe::ParserConfig::with_all_options(),
    )
    .unwrap();

    debug!("is_arm64ec: {}", pe.is_arm64ec());
    debug!("is_arm64x: {}", pe.is_arm64x());

    let imagebase = pe.optional_header().imagebase();
    let loadconfig = pe.load_configuration().unwrap();

    // Add structure type associated with CHPE ARM64 metadata (`IMAGE_ARM64EC_METADATA`)
    // this is not required but it can be useful to access the values of this structure
    // in BinaryNinja.
    if let Some(lief::pe::CHPEMetadata::ARM64(_arm64)) = loadconfig.chpe_metadata() {
        add_chpe_arm64_types(bv, &loadconfig);
    }

    // Reanalyze all the functions that have already been discovered by BinaryNinja.
    // We store the VA of the functions identified during BinaryNinja's default analysis stages.
    // This is important because using `add_function` will undefine these existing functions,
    // ensuring they are disassembled according to the correct architecture.
    //
    // We cannot use the `bv.functions()` iterator directly as undefining a function will
    // invalidate the iterator. Therefore, we use the `map().collect()` to make sure it
    // is independent from the iterator
    let func_found: Vec<u64> = bv.functions().iter().map(|f| f.start()).collect();
    for addr in func_found {
        add_function(bv, &pe, addr);
    }

    let windows_arm64 = Platform::by_name("windows-aarch64").unwrap().to_owned();
    let windows_x64 = Platform::by_name("windows-x86_64").unwrap().to_owned();

    // Iterate over the exceptions table and add functions for the associated architecture
    for exception in pe.exceptions() {
        match exception {
            lief::pe::RuntimeExceptionFunction::X86_64(x64) => {
                let addr: u64 = imagebase + (x64.rva_start() as u64);
                bv.add_auto_function(&windows_x64, addr);
            }

            lief::pe::RuntimeExceptionFunction::AArch64(arm64) => {
                let addr: u64 = imagebase + (arm64.rva_start() as u64);
                bv.add_auto_function(&windows_arm64, addr);
            }
        }
    }

    // Try to identify more functions from (guarded) functions table referenced in
    // the LoadConfiguration
    loadconfig
        .guard_cf_functions()
        .map(|f| imagebase + (f.rva() as u64))
        .for_each(|addr| add_function(bv, &pe, addr));

    loadconfig
        .guard_address_taken_iat_entries()
        .map(|f| imagebase + (f.rva() as u64))
        .for_each(|addr| add_function(bv, &pe, addr));

    loadconfig
        .guard_long_jump_targets()
        .map(|f| imagebase + (f.rva() as u64))
        .for_each(|addr| add_function(bv, &pe, addr));

    loadconfig
        .guard_eh_continuation_functions()
        .map(|f| imagebase + (f.rva() as u64))
        .for_each(|addr| add_function(bv, &pe, addr));

    // Restart BinaryNinja analysis to take into account functions discovered in the
    // previous steps
    bv.update_analysis();
}

struct Arm64Enhancer;

impl Command for Arm64Enhancer {
    fn action(&self, view: &BinaryView) {
        enhance_with_lief(view)
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("LIEF - ARM64EC Enhancer")
        .with_level(LevelFilter::Debug)
        .init();
    register_command("LIEF\\ARM64EC Enhancer", "", Arm64Enhancer {});
    true
}
