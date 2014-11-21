/*  =========================================================================
    curve.h - Curve public interface

    -------------------------------------------------------------------------
    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of the Curve authentication and encryption library.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
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
