{-| Alcor lock-related types and type classes

-}

{-
-}

module Alcor.Locking.Types
  ( Lock
  , lockImplications
  ) where

{-| The type class of being a lock

As usual, locks need to come with an order, the lock order, and
be an instance of Show, so that malformed requests can meaningfully
be reported.

Additionally, in Alcor we also have group locks, like a lock for all
nodes. While those group locks contain infinitely many locks, the set
of locks a single lock is included in is always finite, and usually
very small. So we take this association from a lock to the locks it
is (strictly) included in as additional data of the type class.

It is a prerequisite that whenever 'a' is implied in 'b', then all locks
that are in the lock order between 'a' and 'b' are also implied in 'b'.

-}

class (Ord a, Show a) => Lock a where
  lockImplications :: a -> [a]
