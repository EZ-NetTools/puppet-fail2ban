class fail2ban::jail::recidive (
  $ignoreip  = undef,
  $action    = 'iptables-allports[name=recidive,protocol=all]',
  $maxretry  = 5,
  $bantime   = 604800, # 1 week
  $findtime  = 86400,  # 1 day
) {

  fail2ban::jail { 'recidive':
    filter    => 'recidive',
    ignoreip  => $ignoreip,
    $action    = $action,
    $logpath   = $fail2ban::log_file,
    $maxretry  = $maxretry,
    $bantime   = $bantime,
    $findtime  = $findtime,
  }
}
