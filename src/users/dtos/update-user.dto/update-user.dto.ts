import { Role } from '../../../common/enums/enum.role';
import { IsEnum } from 'class-validator';
export class UpdateUserDto {
  @IsEnum(Role) role: Role;
}
