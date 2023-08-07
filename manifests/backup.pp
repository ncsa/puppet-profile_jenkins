# @summary Configure jenkins backups
#
# @param locations
#   files and directories that are to be backed up#
#   include profile_xcat::master::backup
#
class profile_jenkins::backup (
  Array[String]     $locations,
) {
  if ( lookup('profile_backup::client::enabled') ) {
    include profile_backup::client

    profile_backup::client::add_job { 'profile_jenkins':
      paths            => $locations,
    }
  }
}
