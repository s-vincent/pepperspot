/*
 * PepperSpot -- The Next Generation Captive Portal
 * Copyright (C) 2008,  Thibault Vançon and Sebastien Vincent
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Contact: thibault.vancon@pepperspot.info
 *          sebastien.vincent@pepperspot.info
 */

/**
 * \file compat.c
 * \brief Compatibility functions.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "compat.h"

#if !defined(HAVE_CLEARENV) || (!defined(_XOPEN_SOURCE))

/* code from miredo */
#ifdef __APPLE__
#include <crt_externs.h>
/**
 * \def environ
 * \brief Extern variable environ replacement
 * for Mac OS X.
 */
#define environ (*_NSGetEnviron())
#else
/**
 * \brief environ variable which contains
 * environment variable.
 *
 * This variable is "extern" of this software.
 */
extern char** environ;
#endif

int clearenv (void)
{
  environ = NULL;
  return 0;
}

#endif

#if !defined(HAVE_DAEMON) || defined(_POSIX_C_SOURCE)

int daemon(int nochdir, int noclose)
{
  pid_t pid = -1;

  pid = fork();

  if(pid == -1) /* error */
  {
    return -1;
  }
  else if(pid == 0) /* child */
  {
    if(setsid() == -1)
    {
      return -1;
    }

    if(!nochdir)
    {
      chdir("/");
    }

    if(!noclose)
    {
      /* open /dev/null */
      int fd = -1;
      if((fd = open("/dev/null", O_RDWR, 0)) != -1)
      {
        /* redirect stdin, stdout and stderr to /dev/null */
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);

        if(fd > -1)
        {
          close(fd);
        }
      }
    }

    return 0;
  }
  else /* father */
  {
    _exit(EXIT_SUCCESS);
  }
}

#endif

