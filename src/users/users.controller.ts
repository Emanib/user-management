import {
  Controller,
  Get,
  Patch,
  Param,
  Body,
  UseGuards,
  Req,
  Post,
  Delete,
  Query,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles/roles.guard';
// import { Roles } from '../common/decorators/roles/roles.decorator';
import { Role } from '../common/enums/enum.role';
import { UpdateUserDto } from './dtos/update-user.dto/update-user.dto';
import { CreateUserDto } from './dtos/create-user.dto/create-user.dto';
import { Roles as KeycloakRoles } from 'nest-keycloak-connect';

@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}
// get profile of user
  // @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@Req() req: any) {
    const u = await this.users.findById(req.user.sub);
    if (!u) {
      return { message: 'User not found' };
    }
    return { id: u.id, email: u.email, name: u.name, role: u.role };
  }

  // Admin-only create user (e.g., to create other admins)
  // create user
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(Role.ADMIN)
  @KeycloakRoles({ roles: ['CREATE_USER'],  })
    @Post('create')
  create(@Body() dto: CreateUserDto) {
    return this.users.create(dto);
  }

  // list users
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(Role.ADMIN)
  @Get()
  async findAll(@Query('page') page = '1', @Query('limit') limit = '10') {
    const pageNumber = parseInt(page, 10);
    const pageSize = parseInt(limit, 10);

    return this.users.findAll({ page: pageNumber, limit: pageSize });
  }
// update role
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(Role.ADMIN)
    @KeycloakRoles({ roles: ['UPDATE_USER'], })
  @Patch(':id/role')
  updateRole(@Param('id') id: string, @Body() dto: UpdateUserDto) {
    return this.users.updateRole(id, dto);
  }
  // remove role
  // @UseGuards(JwtAuthGuard, RolesGuard)
// @Roles(Role.ADMIN)
    @KeycloakRoles({ roles: ['UPDATE_USER'],  })
@Patch(':id/role/remove')
async removeRole(@Param('id') id: string) {
  return this.users.removeRole(id);
}

// delete user
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(Role.ADMIN)
    @KeycloakRoles({ roles: ['DELETE_USER'],  })

  @Delete(':id')
  async delete(@Param('id') id: string) {
    return this.users.delete(id);
  }
}
