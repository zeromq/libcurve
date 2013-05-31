/*  =========================================================================
    clab.h - CLAB wrapper

    -------------------------------------------------------------------------
    Copyright (c) 1991-2013 iMatix Corporation <www.imatix.com>
    Copyright other contributors as noted in the AUTHORS file.

    This file is part of CLAB, the space for experimental C classes.

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

#ifndef __CLAB_H_INCLUDED__
#define __CLAB_H_INCLUDED__

//  CLAB version macros for compile-time API detection

#define CLAB_VERSION_MAJOR 1
#define CLAB_VERSION_MINOR 0
#define CLAB_VERSION_PATCH 0

#define CLAB_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define CLAB_VERSION \
    CLAB_MAKE_VERSION(CLAB_VERSION_MAJOR, CLAB_VERSION_MINOR, CLAB_VERSION_PATCH)

#include <czmq.h>
#if CZMQ_VERSION < 10400
#   error "FileMQ needs CZMQ/1.4.0 or later"
#endif

//  Classes in the API

#include "cl_curve.h"

#endif
