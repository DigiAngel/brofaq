# FAQ for Bro


## Fix sendmail after install
Sometimes you install sendmail of something like it, after install.  If bro doesn't see sendmail during ./configure you will have to add:
~~~
Sendmail = /usr/sbin/sendmail
~~~
to your broctl.cfg


## Disable checksums
add:
~~~
broargs = --no-checksums
~~~
to your broctl.cfg

OR
add:
~~~
redef ignore_checksums = T;
~~~
to your local.bro


## Add BPF filtering
add:
~~~
broargs = --filter '<your filter here>'
~~~
to your broctl.cfg


## Disable an analyzer
For each analyzer you want to disable add the below to your already existing bro_init or create a new one like below:
~~~
event bro_init()
    {
    Log::disable_stream(Syslog::LOG);
    Analyzer::disable_analyzer(Analyzer::ANALYZER_SYSLOG);
    }
~~~
to your local.bro


## Disable entry types in in a log
Add a new function to local.bro like the below:
~~~
function filter_weird (rec: Weird::Info) : bool
      {
      return /binpac exception/ ! in rec$name;
      }
~~~
Then add the below fo your already existing bro_init, or create new one like below:
~~~
event bro_init()
      {
      local filter: Log::Filter = Log::get_filter(Weird::LOG, "default");
      filter$pred=filter_weird;
      Log::add_filter(Weird::LOG, filter);
      }
~~~
