
import Alcor.Daemon (OptType)
import qualified Alcor.Daemon as Daemon
import qualified Alcor.Kvmd as Kvmd (start)
import Alcor.Runtime (AlcorDaemon(..))

-- | Options list and functions.
options :: [OptType]
options =
  [ Daemon.oNoDaemonize
  , Daemon.oNoUserChecks
  , Daemon.oDebug
  , Daemon.oSyslogUsage
  ]

-- | Main function.
main :: IO ()
main =
  Daemon.genericMain AlcorKvmd options
    (\_ -> return . Right $ ())
    (\_ _ -> return ())
    (\_ _ _ -> Kvmd.start)
