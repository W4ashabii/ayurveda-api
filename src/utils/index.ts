import { HTTP_STATUS } from '../constant';

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
}

export const createSuccessResponse = <T>(
  data: T,
  message?: string,
  statusCode: number = HTTP_STATUS.OK
): { response: ApiResponse<T>; statusCode: number } => ({
  response: {
    success: true,
    data,
    message,
  },
  statusCode,
});

export const createErrorResponse = (
  message: string,
  statusCode: number = HTTP_STATUS.INTERNAL_SERVER_ERROR,
  error?: string
): { response: ApiResponse<null>; statusCode: number } => ({
  response: {
    success: false,
    message,
    error,
  },
  statusCode,
});
