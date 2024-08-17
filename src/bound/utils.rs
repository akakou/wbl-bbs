pub(crate) mod index_helper {
    pub(crate) fn bases(bit_length: usize) -> (usize, usize) {
        let input_base = 3 * bit_length;
        let output_base = 2 * bit_length;

        return (input_base, output_base);
    }

    pub(crate) fn lens(bit_length: usize) -> (usize, usize) {
        let (input_base, output_base) = bases(bit_length);

        let input_len = input_base + 1;
        let output_len = output_base + 1;

        return (input_len, output_len);
    }
}
