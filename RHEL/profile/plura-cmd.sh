function log2syslog
{
   declare command
   command=$BASH_COMMAND
   logger -p local0.notice -t bash -i -- $USER : $PWD : $command

}
trap log2syslog DEBUG
