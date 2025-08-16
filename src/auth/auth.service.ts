import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private users: UsersService,
    private jwt: JwtService,
    private config: ConfigService,
    private prisma: PrismaService,
  ) {}

  async register(dto: { email: string; password: string; name?: string }) {
    const existing = await this.users.findByEmail(dto.email);
    if (existing) throw new BadRequestException('Email already in use');
    return this.users.create({ ...dto });
  }

  async validateUser(email: string, password: string) {
    const user = await this.users.findByEmail(email);
    if (!user) return null;
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return null;
    // strip password
    const { password: _, ...safe } = user;
    return safe;
  }

  private async signTokens(user: { id: string; email: string; role: string }) {
    const payload = { sub: user.id, email: user.email, role: user.role };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: this.config.get('JWT_ACCESS_SECRET'),
        expiresIn: this.config.get('ACCESS_TOKEN_TTL', '15m'),
      }),
      this.jwt.signAsync(payload, {
        secret: this.config.get('JWT_REFRESH_SECRET'),
        expiresIn: this.config.get('REFRESH_TOKEN_TTL', '7d'),
      }),
    ]);
    return { accessToken, refreshToken };
  }

  private refreshExpiryToDate() {
    const dur = this.config.get('REFRESH_TOKEN_TTL', '7d');
    // naive: 7d, 15m, 24h → convert to ms
    const unit = dur.slice(-1);
    const n = parseInt(dur.slice(0, -1), 10);
    const ms = unit === 'd' ? n*24*60*60*1000 : unit === 'h' ? n*60*60*1000 : n*60*1000;
    return new Date(Date.now() + ms);
  }

  async login(user: { id: string; email: string; role: string }) {
    const tokens = await this.signTokens(user);
    const hashed = await bcrypt.hash(tokens.refreshToken, 10);
    await this.prisma.refreshToken.create({
      data: { userId: user.id, hashedToken: hashed, expiresAt: this.refreshExpiryToDate() },
    });
    return tokens;
  }

  async refresh(userIdFromBody: string, incomingToken: string) {
    // Verify signature & expiry first
    let decoded: any;
    try {
      decoded = await this.jwt.verifyAsync(incomingToken, {
        secret: this.config.get('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (decoded.sub !== userIdFromBody) throw new UnauthorizedException('Token/user mismatch');

    const tokens = await this.prisma.refreshToken.findMany({
      where: { userId: userIdFromBody, revoked: false, expiresAt: { gt: new Date() } },
    });

    // Compare with bcrypt
    const match = await (async () => {
      for (const t of tokens) {
        const ok = await bcrypt.compare(incomingToken, t.hashedToken);
        if (ok) return t;
      }
      return null;
    })();

    if (!match) throw new UnauthorizedException('Refresh token not found or revoked');

    // Rotate: revoke old, issue new
    await this.prisma.refreshToken.update({ where: { id: match.id }, data: { revoked: true } });

    const user = await this.users.findById(userIdFromBody);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    const { accessToken, refreshToken } = await this.signTokens({
      id: user.id, email: user.email, role: user.role,
    });

    const newHash = await bcrypt.hash(refreshToken, 10);
    await this.prisma.refreshToken.create({
      data: { userId: user.id, hashedToken: newHash, expiresAt: this.refreshExpiryToDate() },
    });

    return { accessToken, refreshToken };
  }

  async logout(userId: string, incomingToken: string) {
    // best-effort revoke matching token
    const tokens = await this.prisma.refreshToken.findMany({
      where: { userId, revoked: false, expiresAt: { gt: new Date() } },
    });
    for (const t of tokens) {
      if (await bcrypt.compare(incomingToken, t.hashedToken)) {
        await this.prisma.refreshToken.update({ where: { id: t.id }, data: { revoked: true } });
        return { revoked: true };
      }
    }
    return { revoked: false };
  }
}

