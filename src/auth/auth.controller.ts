import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dtos/register.dto/register.dto';
import { LoginDto } from './dtos/login.dto/login.dto';
// import { LocalAuthGuard } from './guards/local-auth.guard';
// import { JwtAuthGuard } from './guards/jwt-auth/jwt-auth.guard';
import { KeycloakAuthGuard } from 'nest-keycloak-connect';
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.auth.register(dto);
  }

  // Passport Local guard puts validated user on req.user
  @UseGuards(KeycloakAuthGuard)
  @Post('login')
  async login(@Req() req: any) {
    return this.auth.login(req.user);
  }

  // @Post('refresh')
  // async refresh(@Body() body: {  refreshToken: string }) {
  //   return this.auth.refresh( body.refreshToken);
  // }

  @UseGuards(KeycloakAuthGuard)
  @Post('logout')
  async logout(@Req() req: any, @Body() body: { refreshToken: string }) {
    return this.auth.logout(req.user.sub, body.refreshToken);
  }

  // Quick protected ping for testing guards
  @UseGuards(KeycloakAuthGuard)
  @Get('protected-ping')
  ping(@Req() req: any) {
    return { ok: true, user: req.user };
  }
}

