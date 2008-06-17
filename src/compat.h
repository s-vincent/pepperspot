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
 * Contact: thibault.vancon@eturs.u-strasbg.fr
 *          vincent@lsiit.u-strasbg.fr
 *
 * You can find a Copy of this license in the LICENSE file
 */

#ifndef COMPAT_H
#define COMPAT_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined (__FreeBSD__)  || defined (__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define s6_addr32   __u6_addr.__u6_addr32
#endif

#ifndef HAVE_CLEARENV

/**
 * \brief clearenv replacement function (non POSIX).
 * Clear the environnement variables.
 * \return 0
 */
int clearenv (void);

#endif

#ifndef HAVE_DAEMON

/**
 * \brief daemon replacement function (non POSIX).
 * \param nochdir if 0, the child change to "/" directory
 * \param noclose if 0, the child redirect stdin, stdout and stderr to /dev/null
 * \return O if OK, -1 otherwise (errno is set).
 */
int daemon(int nochdir, int noclose);

#endif

#ifdef __cplusplus
}
#endif 

#endif /* COMPAT_H */

