import { Controller, Get, Patch, Param, Body, UseGuards, Req, Post } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles/roles.guard';
import { Roles } from '../common/decorators/roles/roles.decorator';
import { Role } from '../common/enums/enum.role';
import { UpdateUserDto } from './dtos/update-user.dto/update-user.dto';
import { CreateUserDto } from './dtos/create-user.dto/create-user.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@Req() req: any) {
    const u = await this.users.findById(req.user.sub);
    if (!u) {
      return { message: 'User not found' };
    }
    return { id: u.id, email: u.email, name: u.name, role: u.role };
  }

  // Admin-only create user (e.g., to create other admins)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Post()
  create(@Body() dto: CreateUserDto) {
    return this.users.create(dto);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Get()
  findAll() {
    return this.users.findAll();
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Patch(':id/role')
  updateRole(@Param('id') id: string, @Body() dto: UpdateUserDto) {
    return this.users.updateRole(id, dto);
  }
}

