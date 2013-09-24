/*  =========================================================================
    curve.h - Curve public interface

    -------------------------------------------------------------------------
    Copyright (c) 1991-2013 iMatix Corporation <www.imatix.com>
    Copyright other contributors as noted in the AUTHORS file.

    This file is part of the Curve authentication and encryption library.

    This is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by the 
    Free Software Foundation; either version 3 of the License, or (at your 
    option) any later version.

    This software is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABIL-
    ITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General 
    Public License for more details.

    You should have received a copy of the GNU Lesser General Public License 
    along with this program. If not, see <http://www.gnu.org/licenses/>.
    =========================================================================
*/

#ifndef __CURVE_H_INCLUDED__
#define __CURVE_H_INCLUDED__

//  libcurve version macros for compile-time API detection

#define CURVE_VERSION_MAJOR 1
#define CURVE_VERSION_MINOR 1
#define CURVE_VERSION_PATCH 0

#define CURVE_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define CURVE_VERSION \
    CURVE_MAKE_VERSION(CURVE_VERSION_MAJOR, CURVE_VERSION_MINOR, CURVE_VERSION_PATCH)

#include <czmq.h>
#if CZMQ_VERSION < 20000
#   error "libcurve needs CZMQ/2.0.0 or later"
#endif

//  Classes in the API

#include "curve_codec.h"
#include "curve_client.h"
#include "curve_server.h"

#endif
