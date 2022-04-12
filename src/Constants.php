<?php

/*
 * Copyright 2020 momosecurity.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Momo\Sec;


class Constants {
    const ERROR_ON_NULL_ENDPOINT = "API endpoint not setting. Setting by '--endpoint' param.";

    const ERROR_ON_OPTION = "Error value on option [%s]";

    const ERROR_ON_NETWORK = "Network Error, code: %s";

    const ERROR_ON_VULNERABLE = "Dependency Vulnerable Found!";

    const ERROR_ON_API = "API return data format error.";

    const PROJECT_LANGUAGE = "php";

    const BUILD_TOOL_TYPE = "Composer";
}