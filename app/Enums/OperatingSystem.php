<?php

namespace App\Enums;

/**
 * Sistema operativo en el que corre el monitor.
 *
 * @package App\Enums
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
enum OperatingSystem: string
{
    case Linux = 'linux';
    case Windows = 'windows';
    case Other = 'other';
}
