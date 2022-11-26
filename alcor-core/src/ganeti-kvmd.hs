
import Ganeti.Daemon (OptType)
import qualified Ganeti.Daemon as Daemon
import qualified Ganeti.Kvmd as Kvmd (start)
import Ganeti.Runtime (GanetiDaemon(..))

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
  Daemon.genericMain GanetiKvmd options
    (\_ -> return . Right $ ())
    (\_ _ -> return ())
    (\_ _ _ -> Kvmd.start)
