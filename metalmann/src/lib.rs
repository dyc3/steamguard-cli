pub mod crafting;
pub mod inventory;
pub mod schema;
pub mod webapi;
pub mod tf2meta;

#[macro_use]
extern crate maplit;

#[cfg(test)]
mod tests {
	#[test]
	fn it_works() {
		let result = 2 + 2;
		assert_eq!(result, 4);
	}
}
