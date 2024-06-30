pub mod internal;


pub trait Data { }

pub trait SizedData : Sized + Data { }
