ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects

                bin_PROGRAMS = meer
                               meer_CPPFLAGS = -I$(top_srcdir) $(LIBFASTJSON_CFLAGS) $(LIBESTR_CFLAGS)
                                       meer_LDADD = $(LIBFASTJSON_LIBS) $(LIBLOGNORM_LIBS) $(LIBESTR_LIBS)

                                               meer_SOURCES = meer.c \
							      config-yaml.c \
							      util.c \
							      daemonize.c \
							      util-strlcpy.c \
							      util-strlcat.c \
							      util-signal.c \
							      util-base64.c \
							      util-md5.c \
							      util-dns.c \
							      get-dns.c \
							      get-geoip.c \
							      get-oui.c \
							      get-fingerprint.c \
							      lockfile.c \
							      counters.c \
							      stats.c \
							      waldo.c \
							      output.c \
							      usage.c \
							      oui.c \
							      geoip.c \
							      calculate-stats.c \
							      ndp-collector.c \
							      decode-json.c \
							      decode-output-json-client-stats.c \
							      output-plugins/pipe.c \
							      output-plugins/external.c \
							      output-plugins/redis.c \
							      output-plugins/bluedot.c \
							      output-plugins/elasticsearch.c \
							      output-plugins/file.c \
							      output-plugins/syslog.c \
							      input-plugins/file.c \
							      input-plugins/redis.c \
							      input-plugins/commandline.c


                                                       install-data-local:

