<?php

use App\Http\Controllers\SecurityDashboardController;
use Illuminate\Support\Facades\Route;

Route::get('/', [SecurityDashboardController::class, 'index'])->name('security.dashboard');
Route::get('/estado', [SecurityDashboardController::class, 'status'])->name('security.status');
