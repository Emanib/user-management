import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dtos/create-user.dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { UpdateUserDto } from './dtos/update-user.dto/update-user.dto';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async create(dto: CreateUserDto) {
     // 1. Check if email already exists
  const existingUser = await this.prisma.user.findUnique({
    where: { email: dto.email },
  });

   if (existingUser) {
    throw new BadRequestException('Email already exists');
  }
    const hash = await bcrypt.hash(dto.password, 10);
    return this.prisma.user.create({
      data: { email: dto.email, password: hash, name: dto.name, role: dto.role },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });
  }
// list of users paginated
async findAll({ page, limit }: { page: number; limit: number }) {
  const skip = (page - 1) * limit;

  const [users, total] = await this.prisma.$transaction([
    this.prisma.user.findMany({
      skip,
      take: limit,
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    }),
    this.prisma.user.count(),
  ]);

  return {
    data: users,
    total,
    page,
    lastPage: Math.ceil(total / limit),
  };
}


  findByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

  findById(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  async delete(id: string) {
  // 1. Check if user exists
  const user = await this.prisma.user.findUnique({ where: { id } });
  if (!user) {
    throw new NotFoundException('User not found');
  }

  // 2. Delete user
  await this.prisma.user.delete({ where: { id } });

  return { message: 'User deleted successfully', id };
}

  updateRole(id: string, dto: UpdateUserDto) {
    return this.prisma.user.update({
      where: { id },
      data: { role: dto.role },
      select: { id: true, email: true, name: true, role: true },
    });
  }
//  Reset role of user
  async removeRole(userId: string) {
  const user = await this.prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new NotFoundException('User not found');

  // Reset role to USER (default)
  const updatedUser = await this.prisma.user.update({
    where: { id: userId },
    data: { role: 'USER' }, // reset to default role
    select: { id: true, email: true, name: true, role: true },
  });

  return { message: 'Role removed successfully', user: updatedUser };
}
}

