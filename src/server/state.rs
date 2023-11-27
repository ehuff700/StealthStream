use std::{
	any::{Any, TypeId},
	collections::HashMap,
};

/// Public wrapper around any state object, exists mostly for ergonomics.
///
/// Because the data used by the state needs to be thread safe, anything you
// store inside the state has to be Send and Sync.
pub struct State<T>(T);

impl<T> State<T>
where
	T: Send + Sync + 'static,
{
	pub fn new(value: T) -> Self { State(value) }

	pub(crate) fn into_inner(self) -> T { self.0 }
}

#[derive(Debug, Default)]
/// InnerState is used by the StealthStream server to store any internal state
/// objects specified by users of the library.
///
/// The data is a `HashMap`, where the key is the TypeId of the object and the
/// value is a Boxed version of Any.
///
/// Because the data used by the state needs to be thread safe, anything you
/// store inside the state has to be Send and Sync.
pub struct InnerState {
	data: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl InnerState {
	/// Inserts a State object into the inner state data map/
	pub fn insert<T>(&mut self, state: State<T>)
	where
		T: Send + Sync + 'static,
	{
		self.data.insert(TypeId::of::<T>(), Box::new(state.into_inner()));
	}

	// Retrieves an item from the inner state object.
	pub fn get<T>(&self) -> Option<&T>
	where
		T: Send + Sync + 'static,
	{
		self.data.get(&TypeId::of::<T>()).and_then(|x| x.downcast_ref())
	}
}
