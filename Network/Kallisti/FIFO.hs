
module Network.Kallisti.FIFO where

import Data.Foldable


data FIFO a = FIFO [a] [a]
type Window a = (a, FIFO a)

instance Functor FIFO where
  fmap g (FIFO f b) = FIFO (fmap g f) (fmap g b)

instance Foldable FIFO where
  foldr g s (FIFO xs ys) = foldr g (foldr g s xs) ys
  foldl' g s (FIFO xs ys) = foldl' g (foldl' g s xs) ys

enqueue :: a -> FIFO a -> FIFO a
enqueue x (FIFO f b) = FIFO f $ x : b

dequeue :: FIFO a -> Window a
dequeue (FIFO (x:f) b) = (x, FIFO f b)
dequeue (FIFO     _ b) = dequeue $ FIFO (reverse b) []

fromList :: [a] -> FIFO a
fromList xs = FIFO xs []

