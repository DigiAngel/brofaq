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
For each analyzer you want to disable add:
~~~
event bro_init()
    {
    Log::disable_stream(Syslog::LOG);
    Analyzer::disable_analyzer(Analyzer::ANALYZER_SYSLOG);
    }
~~~
to your local.bro
