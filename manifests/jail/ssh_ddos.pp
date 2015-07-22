class fail2ban::jail::ssh_ddos (
  $ignoreip  = '',
  $action    = '',
  $maxretry  = '',
  $bantime   = '',
  $findtime  = '',
  $port      = 'ssh',
) {
  
  $logpath = $osfamily ? {
    'Debian' => '/var/log/auth.log',
    default  => '/var/log/secure',
  }
  
  fail2ban::jail { 'ssh-ddos':
    filter    => 'sshd-ddos',
    ignoreip  => $ignoreip,
    port      => $port,
    protocol  => 'tcp',
    $action    = $action,
    $logpath   = $logpath,
    $maxretry  = $maxretry,
    $bantime   = $bantime,
    $findtime  = $findtime,
  }
}
