<?php

use App\Http\Controllers\SecurityDashboardController;
use Illuminate\Support\Facades\Route;

Route::get('/', [SecurityDashboardController::class, 'index'])->name('security.dashboard');
Route::get('/estado', [SecurityDashboardController::class, 'status'])->name('security.status');
Route::get('/recursos', [SecurityDashboardController::class, 'resources'])->name('security.resources');
Route::get('/ataques', [SecurityDashboardController::class, 'attacks'])->name('security.attacks');
