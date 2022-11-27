{-| Tags

This module holds all the tag interpretation done by htools.

-}

{-
-}

module Alcor.HTools.Tags
  ( hasStandbyTag
  , getMigRestrictions
  , getRecvMigRestrictions
  , getLocations
  ) where

import Control.Monad (guard, (>=>))
import Data.List (isPrefixOf, isInfixOf, stripPrefix)
import Data.Maybe (mapMaybe)
import qualified Data.Set as S

import qualified Alcor.HTools.Node as Node
import Alcor.HTools.Tags.Constants ( standbyPrefix
                                    , migrationPrefix, allowMigrationPrefix
                                    , locationPrefix )

-- * Predicates

-- | Predicate of having a standby tag.
hasStandbyTag :: Node.Node -> Bool
hasStandbyTag = any (standbyPrefix `isPrefixOf`) . Node.nTags

-- * Utility functions

-- | Htools standard tag extraction. Given a set of cluster tags,
-- take those starting with a specific prefix, strip the prefix
-- and append a colon, and then take those node tags starting with
-- one of those strings.
getTags :: String -> [String] -> [String] -> S.Set String
getTags prefix ctags ntags = S.fromList
  (mapMaybe (stripPrefix prefix) ctags >>= \ p ->
    filter ((p ++ ":") `isPrefixOf`) ntags)

-- * Migration restriction tags

-- | Given the cluster tags extract the migration restrictions
-- from a node tag.
getMigRestrictions :: [String] -> [String] -> S.Set String
getMigRestrictions = getTags migrationPrefix

-- | Maybe split a string on the first single occurence of "::" return
-- the parts before and after.
splitAtColons :: String -> Maybe (String, String)

splitAtColons (':':':':xs) = do
  guard $ not ("::" `isInfixOf` xs)
  return ("", xs)

splitAtColons (x:xs) = do
  (as, bs) <- splitAtColons xs
  return (x:as, bs)

splitAtColons _ = Nothing

-- | Get the pairs of allowed migrations from a set of cluster tags.
migrations :: [String] -> [(String, String)]
migrations = mapMaybe $ stripPrefix allowMigrationPrefix >=> splitAtColons

-- | Given the cluster tags, extract the set of migration restrictions
-- a node is able to receive from its node tags.
getRecvMigRestrictions :: [String] -> [String] -> S.Set String
getRecvMigRestrictions ctags ntags =
  let migs = migrations ctags
      closure tag = (:) tag . map fst $ filter ((==) tag . snd) migs
  in S.fromList $ S.elems (getMigRestrictions ctags ntags) >>= closure

-- * Location tags

-- | Given the cluster tags, extract the node location tags
-- from the node tags.
getLocations :: [String] -> [String] -> S.Set String
getLocations = getTags locationPrefix
