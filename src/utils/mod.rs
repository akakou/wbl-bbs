use blake2::{Blake2s256, Digest};
use snowbridge_amcl::bls381::{big::Big, rom};

pub(crate) fn order() -> Big {
    Big::new_ints(&rom::CURVE_ORDER)
}

pub(crate) fn hash(buf : &[u8]) -> Big {
    let mut hash = Blake2s256::new();
    hash.update(buf);     

    let h = hash.finalize();
    let c = Big::from_bytes(&h);

    return c;
}
