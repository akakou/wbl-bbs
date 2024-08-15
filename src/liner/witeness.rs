use snowbridge_amcl::bls381::big::Big;


pub struct Witness (pub Vec<Big>);

impl Witness {
    pub fn new(input: usize) -> Self {
        Witness(vec![Big::new(); input])
    }
}
