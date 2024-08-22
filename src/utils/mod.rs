use snowbridge_amcl::bls381::{big::Big, rom};

pub(crate) fn order() -> Big {
    Big::new_ints(&rom::CURVE_ORDER)
}
