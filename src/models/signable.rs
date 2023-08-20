pub trait Signable {
    fn is_signed(&self) -> bool;
    fn signed(&mut self) -> &mut bool;
}
